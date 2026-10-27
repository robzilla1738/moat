import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { FlowStore } from "../src/flows.ts";
import { parseAdGuardQueryLog, parsePiholeQueries, storeObservations, dnsClients, pollResolver } from "../src/dns.ts";
import { DkFeed, toDkEvent } from "../src/dkfeed.ts";
import { startServer } from "../src/server.ts";
import { enroll, syncOnce, signedPost } from "../src/agent.ts";
import { Signer } from "../src/signer.ts";
import { serveSigner, signerClient } from "../src/signer-service.ts";
import { Controller } from "../src/controller.ts";
import { generateKeyPair } from "../src/crypto.ts";
import { Moatctl } from "../src/moatctl.ts";
import { bootstrap, fixture, MOATCTL } from "./helpers.ts";

test("flow store: batched inserts, duplicates ignored, gaps found, rollups, retention and quota", () => {
  const fs = new FlowStore(join(mkdtempSync(join(tmpdir(), "flows-")), "flows.db"));
  const rec = (seq: number, at: string) => ({ seq, at, kind: "flow", app: "curl", destination: "203.0.113.50", port: 443, transport: "tcp", verdict: "deny" as const, rule: "default:coding-session" });
  const r1 = fs.insertBatch("omarchy", [rec(1, "2026-09-01T10:00:00Z"), rec(2, "2026-10-26T10:05:00Z"), rec(3, "2026-10-26T10:10:00Z")]);
  assert.deepEqual([r1.inserted, r1.duplicates], [3, 0]);
  const r2 = fs.insertBatch("omarchy", [rec(3, "2026-10-26T10:10:00Z"), rec(7, "2026-10-26T11:00:00Z")]);
  assert.deepEqual([r2.inserted, r2.duplicates], [1, 1]);
  assert.deepEqual(r2.gaps, [], "a hole is pending (the endpoint resends), not a gap");
  assert.deepEqual(r2.pending, [[4, 6]]);
  assert.equal(r2.acked, 3, "acknowledged only up to the contiguous high-water");
  const r3 = fs.insertBatch("omarchy", [], [[4, 6]]);
  assert.deepEqual(r3.gaps, [[4, 6]], "declared lost by the endpoint");
  assert.equal(r3.acked, 7);
  const roll = fs.rollups({ sinceHour: "2026-10-26T00:00:00Z" }) as { hour: string; flows: number }[];
  assert.equal(roll.find((x) => x.hour === "2026-10-26T10:00:00Z")!.flows, 2);
  const ret = fs.retain(new Date("2026-10-26T12:00:00Z"));
  assert.equal(fs.recent({ limit: 10 }).length, 3, "the September record is past 30 days");
  assert.ok(ret.raw_before!.startsWith("2026-09-26"));
  for (let i = 0; i < 3000; i++) fs.insertBatch("mbp", [{ seq: i + 1, at: new Date(Date.parse("2026-10-20T00:00:00Z") + i * 60_000).toISOString(), kind: "flow", destination: "x".repeat(200) }]);
  const before = fs.sizeBytes();
  const q = fs.retain(new Date("2026-10-26T12:00:00Z"), { rawDays: 30, rollupDays: 90, maxBytes: Math.floor(before / 3) });
  assert.ok(q.trimmed_for_quota > 0, "quota trimmed the oldest raw records");
  assert.ok(fs.sizeBytes() <= before);
  assert.equal(fs.recent({ limit: 5000 }).length < 3003, true);
  assert.equal(fs.recent({ limit: 99999 }).length <= 1000, true, "queries are bounded");
});

test("notifier: ntfy gets only an opaque reference; details need an authenticated fetch", async () => {
  const sent: { url: string; body: string; headers: Record<string, string> }[] = [];
  const f = fixture();
  f.c.notifier.fetchImpl = async (url, init) => (sent.push({ url, body: init.body, headers: init.headers }), { status: 200 });
  f.c.notifier.publicUrl = "https://mini.tailnet.ts.net";
  const dest = f.c.notifier.addDestination({ name: "phone", kind: "ntfy", url: "https://ntfy.example/moat-robert", min_urgency: "high" });
  assert.match(String(dest.cloud_dependency), /opaque reference/);
  assert.throws(() => f.c.notifier.addDestination({ name: "x", kind: "webhook", url: "http://example.com/hook" }), /https/);
  const iid = f.c.raise({ kind: "blocked_connection", device: "mbp-m1", session: "s1", destination: "oss-cn-beijing.aliyuncs.com", port: 443, rule: "default:coding-session", reason: "blocked by the coding-session default", urgency: "high", ref: "seq:1", at: new Date().toISOString() });
  f.c.raise({ kind: "blocked_connection", device: "mbp-m1", session: "s1", destination: "x.example", port: 443, rule: "r", reason: "low thing", urgency: "low", ref: "seq:2", at: new Date().toISOString() });
  const res = await f.c.notifier.deliver();
  assert.equal(res.delivered, 1, "low urgency stays in the dashboard");
  assert.doesNotMatch(sent[0]!.body, /aliyuncs|beijing|mbp|coding/);
  const ref = /ref ([A-Za-z0-9_-]+)/.exec(sent[0]!.body)![1]!;
  assert.match(sent[0]!.headers.Click!, new RegExp(`/#/r/${ref}$`));
  assert.equal(f.c.notifier.resolveRef(ref), iid);
});

test("DNS-only integrations: AdGuard Home and Pi-hole records carry no process, app or bytes", async () => {
  const ag = parseAdGuardQueryLog("adguard", { data: [{ client: "192.168.1.40", time: "2026-10-26T12:00:00Z", question: { name: "ads.example.", type: "A" }, reason: "FilteredBlackList", status: "NOERROR" }, { client: "192.168.1.41", time: "2026-10-26T12:00:01Z", question: { name: "plex.tv", type: "AAAA" }, reason: "NotFilteredNotFound" }] });
  assert.deepEqual(ag.map((o) => [o.name, o.blocked]), [["ads.example", true], ["plex.tv", false]]);
  const ph = parsePiholeQueries("pihole", { queries: [{ domain: "Telemetry.Example", client: { ip: "192.168.1.50" }, time: 1793448000, type: "A", status: "GRAVITY" }] });
  assert.equal(ph[0]!.blocked, true);
  assert.equal(ph[0]!.name, "telemetry.example");
  const f = fixture();
  storeObservations(f.c.db, ag, true, "adguard");
  const clients = dnsClients(f.c.db);
  assert.equal(clients.length, 2);
  for (const c of clients) {
    assert.equal(c.coverage, "dns-only");
    assert.match(c.claim, /No app, process/);
    assert.equal("app" in c || "process" in c || "bytes" in c, false);
  }
  const down = await pollResolver({ id: "adguard", kind: "adguard", url: "http://127.0.0.1:1" }, async () => { throw new Error("ECONNREFUSED"); });
  assert.equal(down.reachable, false);
});

test("Digital Kingdom feed: enforcer reports, never independent observations; durable cursor", async () => {
  const f = fixture();
  f.c.raise({ kind: "blocked_connection", device: "mbp-m1", session: "s1", app: "curl", destination: "oss-cn-beijing.aliyuncs.com", port: 443, transport: "tcp", rule: "default:coding-session", revision: 4, reason: "blocked", urgency: "high", ref: "seq:1", at: "2026-10-26T12:00:00Z" });
  f.c.raise({ kind: "coverage_lost", device: "omarchy", destination: "-", reason: "nft failed", urgency: "high", ref: "seq:2", at: "2026-10-26T12:01:00Z" });
  const posts: string[] = [];
  const feed = new DkFeed(f.c.db, "https://dk.local", "dk_src_key", async (url, init) => (posts.push(init.body), assert.equal(init.headers.authorization, "Bearer dk_src_key"), assert.equal(url, "https://dk.local/ingest/events"), { status: 202 }));
  const r = await feed.push();
  assert.equal(r.sent, 2);
  const evs = (JSON.parse(posts[0]!) as { events: { action: string; outcome: string; agent?: { origin: string } }[] }).events;
  assert.equal(evs[0]!.action, "tool_invocation");
  assert.equal(evs[0]!.outcome, "blocked");
  assert.equal(evs[0]!.agent!.origin, "policy_enforcer");
  assert.equal(evs[1]!.action, "sensor_unavailable");
  assert.equal((await feed.push()).sent, 0, "cursor persisted");
  assert.equal(toDkEvent({ kind: "policy_rejected" } as never), null);
});

test("end to end over HTTP: separate signer process boundary, enrollment, mutually authenticated sync into a moatd state dir", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moat-e2e-"));
  const moatctl = new Moatctl(MOATCTL);
  const owner = generateKeyPair();
  const sk = generateKeyPair();
  const sock = join(dir, "signer.sock");
  const signerSrv = serveSigner(new Signer({ seedHex: sk.seedHex, ownerPublicKeysHex: [owner.publicHex], moatctl, statePath: join(dir, "signer-state.json") }), sock);
  await new Promise((r) => setTimeout(r, 100));
  const signer = await signerClient(sock);
  assert.equal(signer.keyId, sk.keyId);
  const c = new Controller({ dataDir: join(dir, "data"), signer, moatctl });
  const ownerToken = c.createToken("robert", "owner").token;
  const srv = startServer(c, { host: "127.0.0.1", port: 0 });
  await new Promise((r) => srv.once("listening", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const call = async (method: string, path: string, body?: unknown, tok = ownerToken) => {
      const r = await fetch(base + path, { method, headers: { "content-type": "application/json", authorization: `Bearer ${tok}` }, body: body ? JSON.stringify(body) : undefined });
      return { status: r.status, json: (await r.json()) as Record<string, unknown> };
    };
    assert.equal((await fetch(base + "/v1/overview")).status, 401, "localhost is not trusted");
    const fx = { c, signer: null as never, signerKey: sk, owner, ownerToken, moatctl, clock: { t: Date.now() } };
    await bootstrap(fx as never);
    const { json: code } = await call("POST", "/v1/enrollment-codes", {});
    const f = (u: string, i: { method: string; headers: Record<string, string>; body: string }) => fetch(u, i) as never;
    const st = await enroll(base, String(code.code), "omarchy", "linux", f);
    // a moatd-like state dir with a spool
    const moatState = join(dir, "moatd");
    mkdirSync(join(moatState, "spool"), { recursive: true });
    const at = new Date().toISOString();
    writeFileSync(join(moatState, "spool/seg-00000000000000000001.jsonl"), [
      { seq: 1, device_id: "omarchy", boot_id: "b", at, event: { type: "restart", boot_id: "b", previous_seq: null, clean_shutdown: true, version: "0.1.0" } },
      { seq: 2, device_id: "omarchy", boot_id: "b", at, event: { type: "rule_counter", rule: "default:coding-session", packets: 2, bytes: 120, scope: "rule" } },
    ].map((x) => JSON.stringify(x)).join("\n") + "\n");
    const r = await syncOnce(st, moatState, f);
    assert.deepEqual([r.uploaded, r.snapshot], [2, true]);
    assert.equal(st.cursor, 2);
    const inbox = readdirSync(join(moatState, "inbox"));
    assert.equal(inbox.length, 1);
    const signed = JSON.parse(readFileSync(join(moatState, "inbox", inbox[0]!), "utf8")) as { key_id: string };
    assert.equal(signed.key_id, sk.keyId, "snapshots are signed by the signer, not the controller");
    const incidents = (await call("GET", "/v1/incidents")).json as unknown as { kind: string }[];
    assert.ok(incidents.some((i) => i.kind === "blocked_connection"));
    // a response signed by anyone but the pinned controller key is refused
    await assert.rejects(signedPost({ ...st, controller_public_hex: generateKeyPair().publicHex }, "/v1/device/sync", {}, f), /response signature invalid/);
    // agents can prepare but not approve over HTTP too
    const agentTok = c.createToken("agent", "agent").token;
    assert.equal((await call("POST", "/v1/policy/proposals/x/approve", {}, agentTok)).status, 403);
  } finally {
    srv.close();
    signerSrv.close();
  }
});
