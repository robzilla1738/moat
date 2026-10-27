/**
 * W16: AdGuard Home and Pi-hole adapters against mock servers over loopback HTTP (documented API shapes, fixtures in
 * test/fixtures), the DNS-only incident path, the Digital Kingdom producer authority and the routes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { ResolverPoller, type HttpFetch } from "../src/resolvers.ts";
import { parseResolverConfig } from "../src/integrations.ts";
import { DkFeed, authorityProblem, intentEvent, producerRegistration, toDkEvent } from "../src/dkfeed.ts";
import { startServer } from "../src/server.ts";
import { fixture, type Fixture } from "./helpers.ts";
import { enroll } from "./w12-helpers.ts";
import { ag, mockAdguard, mockPihole, ph } from "./resolver-mocks.ts";

const http: HttpFetch = (u, i) => fetch(u, i) as never;
const obsCount = (f: Fixture, r: string) => (f.c.db.prepare("SELECT COUNT(*) AS n FROM dns_observations WHERE resolver = ?").get(r) as { n: number }).n;
const tick = (f: Fixture, ms = 60_000) => (f.clock.t += ms);

test("AdGuard Home: version check, checkpoint, restart without duplicates, same-instant queries, retention and budget gaps", async () => {
  const f = fixture("2026-10-27T17:01:00Z");
  const m = await mockAdguard();
  try {
    const cfg = { id: "adguard", kind: "adguard" as const, url: m.url, username: "moat", password: "s3cret", pageSize: 2, maxPages: 2 };
    let p = new ResolverPoller(f.c.db, cfg, http, f.c.now);
    let r = await p.poll();
    assert.equal(r.health, "ok");
    assert.equal(r.version, "v0.107.52");
    assert.equal(r.stored, 2, "the first poll imports one page and records where history starts");
    assert.deepEqual(r.observations.map((o) => o.name), ["ads.doubleclick.net", "plex.tv"], "trailing dot removed, lowercased");
    assert.equal(r.observations[0]!.blocked, true);
    assert.equal(r.observations[1]!.blocked, false);
    assert.ok(p.state().started_at, "history start recorded");
    // restart: a new poller on the same database polls again; nothing is duplicated or invented
    tick(f);
    p = new ResolverPoller(f.c.db, cfg, http, f.c.now);
    r = await p.poll();
    assert.equal(r.stored, 0);
    assert.equal(obsCount(f, "adguard"), 2);
    // new queries, two at the same instant as each other, one at the checkpoint instant from another client
    m.state.entries.unshift(ag("2026-10-27T17:00:05Z", "192.168.1.40", "a.example"), ag("2026-10-27T17:00:05Z", "192.168.1.41", "a.example"), ag("2026-10-27T17:00:03.000000001Z", "192.168.1.99", "same-instant.example"));
    tick(f);
    r = await p.poll();
    assert.equal(r.stored, 3, "all three new queries, none of the old ones");
    assert.deepEqual(r.gaps, []);
    // retention: the resolver dropped everything we had not seen yet beyond what one poll reaches
    m.state.entries = [ag("2026-10-27T17:10:02Z", "192.168.1.40", "n2.example"), ag("2026-10-27T17:10:01Z", "192.168.1.40", "n1.example")];
    tick(f);
    r = await p.poll();
    assert.equal(r.stored, 2);
    assert.equal(r.gaps.length, 1);
    assert.match(r.gaps[0]!.reason, /no longer has these queries/);
    // budget: more new history than 2 pages of 2
    m.state.entries = [...Array.from({ length: 7 }, (_, i): Record<string, unknown> => ag(`2026-10-27T17:20:0${7 - i}Z`, "192.168.1.40", `b${7 - i}.example`)), ...m.state.entries];
    tick(f);
    r = await p.poll();
    assert.equal(r.stored, 4);
    assert.match(r.gaps[0]!.reason, /more history than the poll budget/);
    const gaps = f.c.db.prepare("SELECT COUNT(*) AS n FROM dns_gaps WHERE resolver = 'adguard'").get() as { n: number };
    assert.equal(gaps.n, 2, "declared gaps are durable");
  } finally {
    await m.close();
  }
});

test("AdGuard Home: unsupported version ingests nothing; bad credentials are auth_failed; an outage backs off and marks clients", async () => {
  const f = fixture("2026-10-27T17:01:00Z");
  const old = await mockAdguard({ version: "v0.106.3" });
  const good = await mockAdguard();
  try {
    let p = new ResolverPoller(f.c.db, { id: "old", kind: "adguard", url: old.url, username: "moat", password: "s3cret" }, http, f.c.now);
    let r = await p.poll();
    assert.equal(r.health, "unsupported_version");
    assert.match(String(r.error), /supported: AdGuard Home v0\.107\.x\. Nothing was ingested/);
    assert.equal(obsCount(f, "old"), 0);
    assert.equal(old.requests.filter((x) => x.startsWith("/control/querylog")).length, 0, "the query log is never read for an unsupported version");
    p = new ResolverPoller(f.c.db, { id: "badpw", kind: "adguard", url: good.url, username: "moat", password: "wrong" }, http, f.c.now);
    r = await p.poll();
    assert.equal(r.health, "auth_failed");
    p = new ResolverPoller(f.c.db, { id: "home", kind: "adguard", url: good.url, username: "moat", password: "s3cret", intervalMs: 30_000 }, http, f.c.now);
    assert.equal((await p.poll()).health, "ok");
    assert.equal((f.c.db.prepare("SELECT reachable FROM dns_clients WHERE resolver = 'home' LIMIT 1").get() as { reachable: number }).reachable, 1);
    await good.close();
    tick(f, 31_000);
    assert.equal(p.due(), true);
    r = await p.poll();
    assert.equal(r.health, "unreachable");
    assert.equal(p.due(), false, "backoff after a failure");
    tick(f, 59_000);
    assert.equal(p.due(), false, "backoff doubles (30 s × 2)");
    tick(f, 2_000);
    assert.equal(p.due(), true);
    assert.equal((f.c.db.prepare("SELECT reachable FROM dns_clients WHERE resolver = 'home' LIMIT 1").get() as { reachable: number }).reachable, 0, "nothing about the resolver's clients is current");
    assert.ok(p.state().last_ok_at, "the last good poll time is kept for evidence age");
  } finally {
    await old.close();
  }
});

test("Pi-hole v6: session auth with one re-authentication, id checkpoint, restart without duplicates, database reset gap, v5 refused", async () => {
  const f = fixture("2026-10-27T17:01:00Z");
  const m = await mockPihole();
  const v5 = await mockPihole({ v5: true });
  const wrong = await mockPihole({ password: "other" });
  try {
    const cfg = { id: "pihole", kind: "pihole" as const, url: m.url, password: "pw" };
    let p = new ResolverPoller(f.c.db, cfg, http, f.c.now);
    let r = await p.poll();
    assert.equal(r.health, "ok");
    assert.equal(r.version, "v6.1");
    assert.equal(r.stored, 3);
    assert.deepEqual(r.observations.filter((o) => o.blocked).map((o) => o.name), ["telemetry.tcl.example"], "GRAVITY is blocked; FORWARDED and CACHE are not");
    // session expired: one re-authentication, the poll succeeds
    m.state.sids.clear();
    m.state.queries.unshift(ph(1044, 1793120500, "192.168.1.50", "new.example"));
    tick(f);
    r = await p.poll();
    assert.equal(r.health, "ok");
    assert.equal(r.stored, 1);
    assert.equal(m.state.logins, 2);
    // restart: a new poller (new session) re-reads; the id checkpoint and the unique source id stop duplicates
    tick(f);
    p = new ResolverPoller(f.c.db, cfg, http, f.c.now);
    r = await p.poll();
    assert.equal(r.stored, 0);
    assert.equal(obsCount(f, "pihole"), 4);
    // the FTL database was replaced: ids restart below the checkpoint
    m.state.queries = [ph(3, 1793121000, "192.168.1.50", "after-reset.example"), ph(2, 1793120990, "192.168.1.50", "x.example")];
    tick(f);
    r = await p.poll();
    assert.equal(r.gaps.length, 1);
    assert.match(r.gaps[0]!.reason, /database was reset/);
    tick(f);
    r = await p.poll();
    assert.equal(r.stored, 2, "after the reset the adapter restarts from the new history instead of skipping it forever");
    // v5 has no /api: unsupported, never guessed at
    r = await new ResolverPoller(f.c.db, { id: "v5", kind: "pihole", url: v5.url, password: "pw" }, http, f.c.now).poll();
    assert.equal(r.health, "unsupported_version");
    assert.match(String(r.error), /Pi-hole v5/);
    r = await new ResolverPoller(f.c.db, { id: "wrongpw", kind: "pihole", url: wrong.url, password: "pw" }, http, f.c.now).poll();
    assert.equal(r.health, "auth_failed");
  } finally {
    await Promise.all([m.close(), v5.close(), wrong.close()]);
  }
});

test("DNS-only incidents: a blocked query reaches the DNS client, never an endpoint; re-polls add no occurrences; endpoint incidents stay on the endpoint", async () => {
  const f = fixture("2026-10-27T17:01:00Z");
  const m = await mockPihole();
  try {
    const mac = enroll(f, "mbp", "macos");
    f.c.integrations.configureResolvers([{ id: "pihole", kind: "pihole", url: m.url, password: "pw" }], http);
    let r = await f.c.integrations.pollResolver("pihole");
    assert.equal(r.raised, 1);
    tick(f, 60_000);
    r = await f.c.integrations.pollResolver("pihole");
    assert.equal(r.raised, 0, "a re-poll of the same query raises nothing");
    const inc = (f.c.incidents() as { kind: string; device_id: string; app: string | null; port: number | null; process_instance: string | null; occurrences: number; reason: string; facts: Record<string, unknown> }[]);
    const dns = inc.filter((i) => i.kind === "dns_blocked");
    assert.equal(dns.length, 1);
    assert.equal(dns[0]!.device_id, "dns:pihole:192.168.1.50");
    assert.deepEqual([dns[0]!.app, dns[0]!.port, dns[0]!.process_instance], [null, null, null], "no app, port or process");
    assert.equal(dns[0]!.occurrences, 1);
    assert.equal(dns[0]!.facts.coverage, "dns-only");
    assert.match(dns[0]!.reason, /DNS-only evidence/);
    // an endpoint's block from its own spool stays on that endpoint
    const at = f.c.now().toISOString();
    f.c.sync(mac, { events: [{ seq: 1, at, event: { type: "flow", attempt: { id: "a1", device_id: "mbp", app: { family: "curl", executable: "/usr/bin/curl" }, remote_ip: "203.0.113.5", remote_port: 443, transport: "tcp", at }, decision: { verdict: "deny", profile: "p", policy_revision: 1 } } } as never] });
    const ep = (f.c.incidents() as { kind: string; device_id: string }[]).find((i) => i.kind === "blocked_connection")!;
    assert.equal(ep.device_id, "mbp");
    await assert.rejects(f.c.integrations.pollResolver("nope"), /no resolver nope/);
  } finally {
    await m.close();
  }
});

test("resolver config: passwords come from files, unknown kinds and duplicates are refused", () => {
  const s = parseResolverConfig(JSON.stringify([{ id: "home", kind: "adguard", url: "http://10.0.0.2:3000", username: "moat", password_file: "/run/secrets/ag" }]), (p) => (assert.equal(p, "/run/secrets/ag"), "pw"));
  assert.equal(s[0]!.password, "pw");
  assert.throws(() => parseResolverConfig(JSON.stringify([{ id: "x", kind: "unbound", url: "http://a" }])), /kind must be/);
  assert.throws(() => parseResolverConfig(JSON.stringify([{ id: "x", kind: "pihole", url: "http://a" }, { id: "x", kind: "pihole", url: "http://b" }])), /twice/);
});

test("Digital Kingdom producer authority: DNS evidence is not sent; intent cannot attest enforcement; refused batches keep the cursor", async () => {
  const f = fixture("2026-10-27T17:01:00Z");
  const m = await mockPihole();
  try {
    enroll(f, "omarchy", "linux");
    f.c.integrations.configureResolvers([{ id: "pihole", kind: "pihole", url: m.url, password: "pw" }], http);
    await f.c.integrations.pollResolver("pihole");
    const reg = producerRegistration(f.c.db);
    assert.equal(reg.kind, "agent_observer");
    assert.deepEqual(reg.asset_ids, ["device:omarchy"], "only enrolled endpoints; DNS clients are not Moat assets");
    assert.deepEqual(reg.allowed_actions, ["tool_invocation", "sensor_unavailable", "sensor_restored"]);
    const assets = new Set(reg.asset_ids);
    assert.equal(toDkEvent({ kind: "dns_blocked", device_id: "dns:pihole:192.168.1.50" } as never), null, "a resolver block is not producer evidence");
    const intent = intentEvent({ rid: 1, id: "s1", device_id: "omarchy", profile: "coding", started_at: f.c.now().toISOString(), intent: "fix tests" });
    assert.equal(authorityProblem(intent, assets), null);
    assert.equal(JSON.stringify(intent).includes("fix tests"), false, "intent text is never sent");
    assert.match(String(authorityProblem({ ...intent, outcome: "blocked" }, assets)), /only an endpoint's policy decision may report outcome blocked/);
    assert.match(String(authorityProblem({ ...intent, agent: { phase: "decision", origin: "runtime_self_report" }, outcome: "allowed" }, assets)), /only an endpoint's policy decision/);
    assert.match(String(authorityProblem({ ...intent, asset_ids: ["dns:pihole:192.168.1.50"] }, assets)), /not an enrolled Moat endpoint/);
    assert.match(String(authorityProblem({ ...intent, action: "side_effect_observed" as never }, assets)), /outside the agent_observer capability/);
    // feed: the DNS incident in the log is skipped; an endpoint gap goes through; a 422 keeps the cursor
    f.c.raise({ kind: "telemetry_gap", device: "omarchy", destination: "-", reason: "events 4-6 lost", urgency: "high", ref: "seq:7", at: f.c.now().toISOString() });
    const bodies: string[] = [];
    let status = 422;
    const feed = new DkFeed(f.c.db, "https://dk.local", "k", async (_u, i) => (bodies.push(i.body), { status }), f.c.now, 1000);
    await assert.rejects(feed.push(), /HTTP 422/);
    assert.equal((feed.health() as unknown as { health: string }).health, "refused");
    assert.equal((feed.health() as { cursor: number }).cursor, 0, "a refused batch is not acknowledged");
    status = 202;
    tick(f, 5_000);
    const r = await feed.push();
    assert.equal(r.sent, 1);
    const sent = JSON.parse(bodies.at(-1)!) as { events: { source_event_id: string; action: string; asset_ids: string[] }[] };
    assert.deepEqual(sent.events.map((e) => e.action), ["sensor_unavailable"]);
    assert.equal(sent.events[0]!.source_event_id, (JSON.parse(bodies[0]!) as { events: { source_event_id: string }[] }).events[0]!.source_event_id, "a retry re-sends the same id (DK deduplicates)");
    assert.equal((await feed.push()).sent, 0);
  } finally {
    await m.close();
  }
});

test("routes: resolver health and DNS clients carry evidence age and no process/bytes; viewers read, only owners poll", async () => {
  const f = fixture(new Date().toISOString());
  const m = await mockAdguard();
  const srv = startServer(f.c, { host: "127.0.0.1", port: 0 });
  await new Promise((r) => srv.once("listening", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const viewer = f.c.createToken("v", "viewer").token;
  const call = async (method: string, path: string, tok = f.ownerToken) => {
    const r = await fetch(base + path, { method, headers: { authorization: `Bearer ${tok}` } });
    return { status: r.status, json: (await r.json()) as unknown };
  };
  try {
    f.c.integrations.configureResolvers([{ id: "adguard", kind: "adguard", url: m.url, username: "moat", password: "s3cret" }], http);
    let res = await call("GET", "/v1/dns/resolvers", viewer);
    assert.equal(res.status, 200);
    assert.equal((res.json as { health: string }[])[0]!.health, "never_polled");
    assert.equal((await call("POST", "/v1/dns/resolvers/adguard/poll", viewer)).status, 403);
    res = await call("POST", "/v1/dns/resolvers/adguard/poll");
    assert.equal((res.json as { stored: number }).stored, 4);
    res = await call("GET", "/v1/dns/resolvers", viewer);
    const h = (res.json as { health: string; evidence_age_s: number; version: string; supported: string; configured: boolean }[])[0]!;
    assert.deepEqual([h.health, h.version, h.supported, h.configured], ["ok", "v0.107.52", "AdGuard Home v0.107.x", true]);
    assert.ok(h.evidence_age_s >= 0);
    assert.equal(JSON.stringify(res.json).includes("s3cret"), false, "credentials are never returned");
    res = await call("GET", "/v1/dns/clients", viewer);
    const clients = res.json as Record<string, unknown>[];
    assert.equal(clients.length, 2);
    for (const c of clients) {
      assert.equal(c.coverage, "dns-only");
      assert.equal(c.resolver_health, "ok");
      assert.equal(typeof c.evidence_age_s, "number");
      for (const k of ["bytes", "bytes_in", "bytes_out", "process", "app", "pid"]) assert.equal(k in c, false, `no ${k}`);
    }
    res = await call("GET", "/v1/integrations/digital-kingdom", viewer);
    assert.equal((res.json as { configured: boolean }).configured, false);
    assert.equal((res.json as { registration: { kind: string } }).registration.kind, "agent_observer");
  } finally {
    srv.close();
    await m.close();
  }
});
