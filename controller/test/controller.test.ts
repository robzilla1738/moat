import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, requestString, signB64, token } from "../src/crypto.ts";
import { Signer } from "../src/signer.ts";
import { authorize, bootstrap, fixture, HOME, type Fixture } from "./helpers.ts";

function deviceHeaders(seed: ReturnType<typeof generateKeyPair>, deviceId: string, body: string, ts: string, nonce = token(18)) {
  return { "x-moat-device": deviceId, "x-moat-ts": ts, "x-moat-nonce": nonce, "x-moat-sig": signB64(seed.privateKey, requestString("POST", "/v1/device/sync", ts, nonce, body)) };
}

function enrollDevice(f: Fixture, id = "omarchy", platform = "linux") {
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  const kp = generateKeyPair();
  f.c.enroll({ code, device_id: id, platform, public_hex: kp.publicHex, capabilities: { capabilities: { session_enforcement: { support: "supported" } } } });
  return kp;
}

async function verifyWithMoatctl(f: Fixture, signed: unknown, adapter: string) {
  const dir = mkdtempSync(join(tmpdir(), "moat-v-"));
  writeFileSync(join(dir, "s.json"), JSON.stringify(signed));
  writeFileSync(join(dir, "k.pub"), f.signer.publicHex);
  return f.moatctl.run(["verify", join(dir, "s.json"), "--pub", join(dir, "k.pub"), "--adapter", adapter]);
}

test("enrollment codes are single-use and expire; device requests are signed, fresh and not replayable", () => {
  const f = fixture();
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  const kp = generateKeyPair();
  const res = f.c.enroll({ code, device_id: "omarchy", platform: "linux", public_hex: kp.publicHex });
  assert.equal(res.signer_key_id, f.signer.keyId);
  assert.throws(() => f.c.enroll({ code, device_id: "other", platform: "linux", public_hex: generateKeyPair().publicHex }), /invalid, used or expired/);
  const { code: c2 } = f.c.createEnrollmentCode(owner);
  f.clock.t += 16 * 60_000;
  assert.throws(() => f.c.enroll({ code: c2, device_id: "late", platform: "linux", public_hex: generateKeyPair().publicHex }), /expired/);

  const body = JSON.stringify({ last_applied: null });
  const ts = new Date(f.clock.t).toISOString();
  const h = deviceHeaders(kp, "omarchy", body, ts);
  assert.equal(f.c.authenticateDevice("POST", "/v1/device/sync", h, body).id, "omarchy");
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", h, body), /replayed/);
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", body, ts), body + " "), /bad device signature/);
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(generateKeyPair(), "omarchy", body, ts), body), /bad device signature/);
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", body, new Date(f.clock.t - 600_000).toISOString()), body), /clock skew/);
  f.c.revokeDevice(owner, "omarchy");
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", body, ts), body), /revoked/);
});

test("roles: viewers and agents cannot change policy; agents may only prepare a diff", async () => {
  const f = fixture();
  const viewer = f.c.authenticate(f.c.createToken("tv", "viewer").token)!;
  const agent = f.c.authenticate(f.c.createToken("claude", "agent").token)!;
  await assert.rejects(f.c.propose(viewer, HOME, "x"), /role/);
  const prop = (await f.c.propose(agent, HOME, "agent-prepared")) as { id: string; broadening: boolean };
  assert.equal(prop.broadening, true);
  await assert.rejects(f.c.approve(agent, prop.id), /role owner/);
  assert.throws(() => f.c.createEnrollmentCode(agent), /role owner/);
});

test("broadening needs the owner key; narrowing does not; stale proposals are refused", async () => {
  const f = fixture();
  const owner = f.c.authenticate(f.ownerToken)!;
  const first = (await f.c.propose(owner, HOME, "initial")) as { id: string; authorization_digest: string };
  await assert.rejects(f.c.approve(owner, first.id), /owner key/);
  // a signature by a key the signer does not trust is not an owner authorization
  await assert.rejects(f.c.approve(owner, first.id, authorize(generateKeyPair(), first.id, first.authorization_digest)), /owner key/);
  // an authorization for a different subject does not transfer
  await assert.rejects(f.c.approve(owner, first.id, authorize(f.owner, "prop_other", first.authorization_digest)), /owner key/);
  const r1 = await f.c.approve(owner, first.id, authorize(f.owner, first.id, first.authorization_digest));
  assert.equal(r1.revision, 1);
  assert.equal(r1.authorized_by, "owner_key");

  const narrower = HOME.replace(/\[\[rules\]\]\nid = "coding-allow-npm"[\s\S]*?provenance = \{[^\n]*\}\n/, "");
  assert.notEqual(narrower, HOME);
  const pN = (await f.c.propose(owner, narrower, "drop npm")) as { id: string; broadening: boolean };
  assert.equal(pN.broadening, false);
  const r2 = await f.c.approve(owner, pN.id);
  assert.equal(r2.authorized_by, "narrowing");

  const broader = narrower + '\n[[rules]]\nid = "coding-allow-pastebin"\naction = "allow"\nselector = { session = { profiles = ["coding-session"] } }\ndestinations = { cidrs = ["203.0.113.0/24"] }\nprovenance = { kind = "git", reference = "x" }\n';
  const pB = (await f.c.propose(owner, broader, "add pastebin")) as { id: string; broadening: boolean; authorization_digest: string };
  assert.equal(pB.broadening, true);
  await assert.rejects(f.c.approve(owner, pB.id), /owner key/);
  // stale: another revision lands first
  const pOther = (await f.c.propose(owner, narrower.replace("Deny unknown egress", "Deny unknown egress (tweak)"), "desc")) as { id: string };
  await f.c.approve(owner, pOther.id);
  await assert.rejects(f.c.approve(owner, pB.id, authorize(f.owner, pB.id, pB.authorization_digest)), /prepared against revision/);
});

test("signed snapshots verify with the Rust core; distribution and receipts are tracked per device", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", "{}", new Date(f.clock.t).toISOString()), "{}");
  const out = f.c.sync(d as never, { last_applied: null });
  assert.ok(out.snapshot, "newer snapshot delivered");
  const v = await verifyWithMoatctl(f, out.snapshot, "linux");
  assert.equal(v.code, 0, v.stderr);
  assert.match(v.stdout, /revision 1/);
  assert.notEqual((await verifyWithMoatctl(f, out.snapshot, "macos")).code, 0, "wrong platform is rejected by the core");
  f.c.sync(d as never, { last_applied: 0, events: [{ seq: 1, at: new Date(f.clock.t).toISOString(), event: { type: "policy_applied", revision: 1, policy_digest: "x" } }] });
  const states = f.c.revisions()[0]!.devices as { state: string }[];
  assert.deepEqual(states.map((s) => s.state).sort(), ["applied", "approved", "distributed"]);
  assert.equal(f.c.sync(d as never, { last_applied: 1 }).snapshot, null, "nothing newer");
});

test("rollback is a new revision with older content, re-authorized by the signer", async () => {
  const f = fixture();
  const owner = f.c.authenticate(f.ownerToken)!;
  await bootstrap(f);
  const narrower = HOME.replace(/\[\[rules\]\]\nid = "coding-allow-npm"[\s\S]*?provenance = \{[^\n]*\}\n/, "");
  await f.c.approve(owner, ((await f.c.propose(owner, narrower, "drop npm")) as { id: string }).id);
  const rb = (await f.c.rollback(owner, 1)) as { id: string; broadening: boolean; rollback_of: number; authorization_digest: string };
  assert.equal(rb.rollback_of, 1);
  assert.equal(rb.broadening, true, "restoring npm broadens relative to revision 2");
  await assert.rejects(f.c.approve(owner, rb.id), /owner key/);
  const r = await f.c.approve(owner, rb.id, authorize(f.owner, rb.id, rb.authorization_digest));
  assert.equal(r.revision, 3);
  assert.equal(f.c.revisions()[0]!.rollback_of, 1);
});

test("incidents group repeats, ignore duplicate records, reopen after acknowledgement, and surface gaps", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", "{}", new Date(f.clock.t).toISOString()), "{}");
  const at = new Date(f.clock.t).toISOString();
  const counter = (seq: number) => ({ seq, at, event: { type: "rule_counter", rule: "default:coding-session", packets: 3, bytes: 180, scope: "rule" } });
  f.c.sync(d as never, { events: [counter(1), counter(2)] });
  let inc = f.c.incidents()[0]!;
  assert.equal(inc.occurrences, 2);
  assert.match(String(inc.reason), /rule-scoped counter/);
  f.c.sync(d as never, { events: [counter(2)] });
  assert.equal(f.c.incidents()[0]!.occurrences, 2, "same record twice is not a new occurrence");
  const owner = f.c.authenticate(f.ownerToken)!;
  assert.throws(() => f.c.acknowledge(owner, inc.id), /expected_revision is required/);
  assert.throws(() => f.c.acknowledge(owner, inc.id, inc.revision + 1), /stale/);
  f.c.acknowledge(owner, inc.id, inc.revision);
  assert.equal(f.c.incidents()[0]!.state, "acknowledged");
  f.c.sync(d as never, { events: [counter(7)] });
  inc = f.c.incidents().find((i) => i.kind === "blocked_connection")!;
  assert.equal(inc.state, "open");
  assert.equal(inc.new_since_ack, 1);
  const gap = f.c.incidents().find((i) => i.kind === "telemetry_gap");
  assert.ok(gap, "seq 3..6 never arrived");
  assert.match(String(gap!.reason), /3–6/);
  f.c.sync(d as never, { events: [{ seq: 8, at, event: { type: "gap", from: 100, to: 120, reason: "spool disk quota reached" } }, { seq: 9, at, event: { type: "coverage_changed", level: "degraded", detail: "nft rejected" } }] });
  assert.ok(f.c.incidents().some((i) => i.kind === "coverage_lost" && i.urgency === "high"));
  assert.throws(() => f.c.sync(d as never, { events: [{ seq: 10, device_id: "mbp-m1", at, event: { type: "policy_applied", revision: 1 } }] }), /own events/);
});

async function blockedSessionIncident(f: Fixture, kp: ReturnType<typeof generateKeyPair>) {
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", "{}", new Date(f.clock.t).toISOString()), "{}");
  const at = new Date(f.clock.t).toISOString();
  f.c.sync(d as never, {
    events: [
      { seq: 1, at, event: { type: "session_started", session_id: "20261026-a1b2", profile: "coding-session", cgroup: "moat.slice/p-coding-session/s-20261026-a1b2", uid: 1000, root_pid: 4242, root_start: 99, boundary: "linux_cgroup" } },
      {
        seq: 2,
        at,
        event: {
          type: "flow",
          attempt: { id: "f1", device_id: "omarchy", app: { family: "curl", executable: "/usr/bin/curl" }, remote_ip: "203.0.113.50", remote_port: 443, transport: "tcp", at, session: { id: "20261026-a1b2", profile: "coding-session", boundary: "linux_cgroup", verified: true }, process: { device_id: "omarchy", boot_id: "b", pid: 4300, start_generation: 7 } },
          decision: { verdict: "deny", profile: "coding-session", policy_revision: 1 },
          chain: ["claude", "zsh", "curl"],
        },
      },
    ],
  });
  return { d, inc: f.c.incidents().find((i) => i.kind === "blocked_connection")! };
}

test("allow once for this session: bound to incident, revision, session and owner; stale actions are rejected", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const { d, inc } = await blockedSessionIncident(f, kp);
  assert.equal(inc.session_id, "20261026-a1b2");
  assert.equal(inc.urgency, "high");
  const owner = f.c.authenticate(f.ownerToken)!;
  const viewer = f.c.authenticate(f.c.createToken("v", "viewer").token)!;
  await assert.rejects(f.c.allowOnce(viewer, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1 }), /role owner/);
  await assert.rejects(f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision + 1, policy_revision: 1 }), /stale: the incident changed/);
  await assert.rejects(f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 7 }), /stale: policy/);
  const g = (await f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1, ttl_seconds: 999_999 })) as { revision: number; authorized_by: string; expires_at: string };
  assert.equal(g.revision, 2);
  assert.equal(g.authorized_by, "temporary_grant_overlay");
  assert.equal(Date.parse(g.expires_at) - f.clock.t, 8 * 3600_000, "TTL clamped to the maximum");
  const effective = f.c.currentRevision()!.effective_source;
  assert.match(effective, /session_ids = \["20261026-a1b2"\]/);
  assert.match(effective, /cidrs = \["203\.0\.113\.50\/32"\]/);
  assert.equal((await f.moatctl.validate(effective)).ok, true);
  // the same action again is stale (policy moved to revision 2)
  await assert.rejects(f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1 }), /stale: policy/);
  // ended session: stale
  f.c.sync(d as never, { events: [{ seq: 3, at: new Date(f.clock.t).toISOString(), event: { type: "session_ended", session_id: "20261026-a1b2", exit_code: 0 } }] });
  await assert.rejects(f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 2 }), /no longer running/);
  // revoking narrows and needs no owner key
  const gid = (f.c.grants()[0] as { id: string }).id;
  const rv = await f.c.revokeGrant(owner, gid);
  assert.equal(rv.authorized_by, "narrowing");
  assert.doesNotMatch(f.c.currentRevision()!.effective_source, /20261026-a1b2/);
});

test("signer refuses grants that are not bounded, and grant inputs are validated", async () => {
  const now = new Date("2026-10-26T12:00:00Z");
  const base = { id: "g", action: "allow", layer: "override", expires_at: "2026-10-26T13:00:00Z", selector: { session: { session_ids: ["s1"] } }, destinations: { cidrs: ["203.0.113.5/32"] }, provenance: { kind: "owner_action", audit_ref: "audit:1" } };
  assert.equal(Signer.boundedGrant(base, now), null);
  assert.match(String(Signer.boundedGrant({ ...base, destinations: { cidrs: ["203.0.113.0/24"] } }, now)), /single address/);
  assert.match(String(Signer.boundedGrant({ ...base, expires_at: "2026-10-28T12:00:00Z" }, now)), /within 24h/);
  assert.match(String(Signer.boundedGrant({ ...base, selector: {} }, now)), /scoped/);
  assert.match(String(Signer.boundedGrant({ ...base, destinations: { any: true } }, now)), /exactly one/);
  assert.match(String(Signer.boundedGrant({ ...base, layer: "explicit" }, now)), /override/);
  assert.match(String(Signer.boundedGrant({ ...base, selector: { session: { any_protected: true } } }, now)), /every protected session/);
  const f = fixture();
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  await assert.rejects(f.c.createGrant(owner, { session_id: "s1", destination: "10.0.0.0/8", port: 443 }), /one IP address or one hostname/);
  await assert.rejects(f.c.createGrant(owner, { destination: "203.0.113.5", port: 443 }), /scoped to a session or an application/);
  await assert.rejects(f.c.createGrant(owner, { session_id: "s1", destination: "203.0.113.5", port: 0 }), /port/);
});

test("harness launch API: profiles from policy and capabilities; self-reports can only assert intent; close is a typed action", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const launcher = f.c.authenticate(f.c.createToken("dispatch", "launcher").token)!;
  const agent = f.c.authenticate(f.c.createToken("claude", "agent").token)!;
  const prof = f.c.launchProfiles("omarchy");
  assert.ok(prof.profiles.includes("coding-session"));
  assert.ok(!prof.profiles.includes("safety-workloads-never-reach-controller"), "rule ids are not profiles");
  assert.match(prof.launch, /never launches anything itself/);
  const { d } = await blockedSessionIncident(f, kp);
  assert.throws(() => f.c.reportIntent(agent, "omarchy", "20261026-a1b2", { assertion: "connection_blocked" }), /may only assert intent/);
  assert.throws(() => f.c.reportIntent(agent, "omarchy", "made-up", { text: "x" }), /created by the endpoint/);
  assert.equal(f.c.reportIntent(agent, "omarchy", "20261026-a1b2", { text: "run tests" }).origin, "runtime_self_report");
  assert.throws(() => f.c.requestClose(agent, "omarchy", "20261026-a1b2"), /role/);
  const a = f.c.requestClose(launcher, "omarchy", "20261026-a1b2");
  const out = f.c.sync(d as never, { last_applied: 1 });
  assert.deepEqual(out.actions.map((x) => x.kind), ["close_session"]);
  assert.equal(out.actions[0]!.id, a.action_id);
  f.c.sync(d as never, { events: [{ seq: 5, at: new Date(f.clock.t).toISOString(), event: { type: "session_ended", session_id: "20261026-a1b2", exit_code: null, signal: 9 } }] });
  assert.equal(f.c.sync(d as never, { last_applied: 1 }).actions.length, 0);
});

test("a silent or stale device never keeps its last coverage claim", () => {
  const f = fixture();
  const kp = enrollDevice(f);
  let d = f.c.devices()[0]!;
  assert.equal(d.stale, true);
  assert.equal(d.effective_coverage, "unknown");
  const row = { id: "omarchy" } as Parameters<typeof f.c.sync>[0];
  f.c.sync(row, { last_applied: null, status: { coverage: "enforced" } });
  d = f.c.devices()[0]!;
  assert.equal(d.stale, false);
  f.clock.t += 11 * 60_000;
  d = f.c.devices()[0]!;
  assert.equal(d.stale, true);
  assert.equal(d.effective_coverage, "degraded");
  assert.match(String(d.coverage_note), /cannot confirm/);
  assert.equal(f.c.overview().devices[0]!.effective_coverage, "degraded");
  void kp;
});

test("trial revisions: start, confirm and rollback are recorded per device; a rollback raises attention", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", "{}", new Date(f.clock.t).toISOString()), "{}");
  const at = new Date(f.clock.t).toISOString();
  f.c.sync(d as never, {
    events: [
      { seq: 1, at, event: { type: "policy_trial_started", revision: 3, fallback_revision: 2, deadline: at } },
      { seq: 2, at, event: { type: "policy_rolled_back", from_revision: 3, to_revision: 2, reason: "trial not confirmed" } },
      { seq: 3, at, event: { type: "policy_trial_started", revision: 4, fallback_revision: 2, deadline: at } },
      { seq: 4, at, event: { type: "policy_trial_confirmed", revision: 4, by_uid: 0, how: "moatd recover confirm" } },
    ],
  });
  const states = f.c.db.prepare("SELECT revision, state FROM device_revisions WHERE device_id = 'omarchy' AND revision >= 3 ORDER BY revision, state").all() as { revision: number; state: string }[];
  assert.deepEqual(states.map((s) => `${s.revision}:${s.state}`), ["3:rolled_back", "3:trial", "4:confirmed", "4:trial"]);
  const inc = f.c.incidents().find((i) => i.kind === "policy_rolled_back");
  assert.ok(inc, "rollback raised");
  assert.equal(inc!.urgency, "high");
  assert.match(inc!.reason, /rolled back to 2/);
});

test("W08: grant status comes from endpoint receipts: pending until applied, rejected stays rejected, expiry is the original deadline", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const { d, inc } = await blockedSessionIncident(f, kp);
  const owner = f.c.authenticate(f.ownerToken)!;
  const g = (await f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1, ttl_seconds: 600 })) as { grant_id: string; revision: number };
  let st = f.c.grantStatus(g.grant_id);
  assert.equal(st.state, "pending", "signed and queued is not active");
  assert.equal(st.authorized_by, "temporary_grant_overlay", "authorizer is the signer's answer");
  assert.equal(st.devices[0]!.state, "queued");
  f.c.sync(d as never, { last_applied: 1 });
  st = f.c.grantStatus(g.grant_id);
  assert.equal(st.state, "pending", "delivery is not application");
  assert.equal(st.devices[0]!.state, "delivered");
  f.c.sync(d as never, { last_applied: 1, receipts: [{ revision: g.revision, state: "rejected", detail: "signature ok, compile failed" }] });
  st = f.c.grantStatus(g.grant_id);
  assert.equal(st.state, "rejected");
  f.c.sync(d as never, { last_applied: g.revision, receipts: [{ revision: g.revision + 0, state: "applied" }] });
  // a later 'applied' receipt for the same revision supersedes nothing: rejected and applied both exist for rev 2,
  // the most specific evidence (rejection at or after the applied revision) keeps it rejected
  assert.equal(f.c.grantStatus(g.grant_id).state, "rejected");
  f.clock.t += 601_000;
  assert.equal(f.c.grantStatus(g.grant_id).state, "expired");
  const revs = f.c.revisions();
  assert.equal(revs[0]!.authorized_by, "temporary_grant_overlay");
  assert.equal(revs[1]!.authorized_by, "owner_key");
});

test("W08: a grant becomes active only with an applied receipt for its revision", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  await bootstrap(f);
  const { d, inc } = await blockedSessionIncident(f, kp);
  const owner = f.c.authenticate(f.ownerToken)!;
  const g = (await f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1, ttl_seconds: 600 })) as { grant_id: string; revision: number };
  f.c.sync(d as never, { last_applied: 1, receipts: [{ revision: 1, state: "applied" }] });
  assert.equal(f.c.grantStatus(g.grant_id).state, "pending", "an older revision's receipt says nothing about the grant");
  f.c.sync(d as never, { last_applied: g.revision, receipts: [{ revision: g.revision, state: "applied" }] });
  const st = f.c.grantStatus(g.grant_id);
  assert.equal(st.state, "active");
  assert.equal(st.devices[0]!.evidence!.revision, g.revision);
  f.clock.t += 11 * 60_000;
  assert.equal(f.c.grantStatus(g.grant_id).devices[0]!.stale, true, "a silent device is marked stale");
});

test("W08: a notification reference opens exactly its incident; new or reordered incidents never retarget it; a deleted one is not substituted", async () => {
  const f = fixture();
  const kp = enrollDevice(f);
  f.c.notifier.addDestination({ name: "phone", kind: "ntfy", url: "https://ntfy.example/moat", min_urgency: "low" });
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", deviceHeaders(kp, "omarchy", "{}", new Date(f.clock.t).toISOString()), "{}");
  const ev = (seq: number, rule: string) => ({ seq, at: new Date(f.clock.t).toISOString(), event: { type: "rule_counter", rule, packets: 1, bytes: 60, scope: "rule" } });
  f.c.sync(d as never, { events: [ev(1, "default:a")] });
  const first = f.c.incidents()[0]!;
  const ref = (f.c.db.prepare("SELECT opaque_ref FROM notify_outbox WHERE incident_id = ?").get(first.id) as { opaque_ref: string }).opaque_ref;
  for (let i = 2; i < 8; i++) {
    f.clock.t += 60_000;
    f.c.sync(d as never, { events: [ev(i, `default:r${i}`)] });
  }
  assert.notEqual(f.c.incidents()[0]!.id, first.id, "the list order changed");
  assert.equal(f.c.notifier.resolveRef(ref), first.id);
  assert.equal(f.c.notifier.resolveRef("not-a-ref"), null);
  f.c.db.prepare("DELETE FROM incidents WHERE id = ?").run(first.id);
  assert.equal(f.c.notifier.resolveRef(ref), first.id, "the reference still names the deleted incident");
  assert.throws(() => f.c.incident(first.id), /no such incident/, "and the API refuses rather than substituting another");
});
