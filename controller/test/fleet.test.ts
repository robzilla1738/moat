/**
 * W13: durable at-least-once events with idempotent ingestion, desired/current reconciliation without last-writer-wins
 * widening, staged rollout, pending/stale devices, revocation, and stale approvals. Real signer + moatctl.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { authorize, bootstrap, fixture, HOME, type Fixture } from "./helpers.ts";
import { CURL_RULE, enroll } from "./w12-helpers.ts";
import { advanceRollout, createRollout, reconciliation, resolveLocalChange, rolloutStatus } from "../src/fleet.ts";

const at = (f: Fixture) => new Date(f.clock.t).toISOString();
const ev = (f: Fixture, seq: number, dest = "203.0.113.1") => ({ seq, at: at(f), event: { type: "flow", attempt: { id: `a${seq}`, device_id: "x", app: { family: "curl", executable: "/usr/bin/curl" }, remote_ip: dest, remote_port: 443, transport: "tcp", at: at(f) }, decision: { verdict: "deny", profile: "p", policy_revision: 1 } } });

async function publish(f: Fixture, source: string) {
  const p = f.c.authenticate(f.ownerToken)!;
  const prop = (await f.c.propose(p, source, "change")) as { id: string; authorization_digest: string };
  return f.c.approve(p, prop.id, authorize(f.owner, prop.id, prop.authorization_digest));
}

test("duplicate, reorder, outage and reconnect: at-least-once with idempotent ingestion and contiguous acks", () => {
  const f = fixture();
  const d = enroll(f, "omarchy", "linux");
  let r = f.c.sync(d, { events: [ev(f, 1), ev(f, 2), ev(f, 4)] });
  assert.equal(r.acked_seq, 2, "3 is missing: the endpoint must keep 4 until 3 arrives");
  assert.deepEqual(r.pending_ranges, [[3, 3]]);
  r = f.c.sync(d, { events: [ev(f, 4), ev(f, 3)] }); // reordered resend + duplicate
  assert.equal(r.acked_seq, 4);
  assert.equal((f.c.flows.db.prepare("SELECT COUNT(*) AS n FROM flows WHERE device_id = 'omarchy'").get() as { n: number }).n, 4, "duplicates stored once");
  const occ = (f.c.incidents() as { occurrences: number; destination: string }[]).find((i) => i.destination === "203.0.113.1")!.occurrences;
  assert.equal(occ, 4, "a resent record is not a new occurrence");
  assert.equal((f.c.incidents() as { kind: string }[]).filter((i) => i.kind === "telemetry_gap").length, 0, "reordering is not loss");
  // controller outage: the device keeps spooling; after 30 minutes it reconnects with the backlog
  f.clock.t += 30 * 60_000;
  assert.equal(reconciliation(f.c).find((x) => x.device === "omarchy")!.state, "current", "no policy yet: nothing to be stale about");
  r = f.c.sync(d, { events: Array.from({ length: 50 }, (_, i) => ev(f, 5 + i)) });
  assert.equal(r.acked_seq, 54);
});

test("reconciliation: pending until the applied receipt, stale when silent; a device never shows current without a receipt", async () => {
  const f = fixture();
  const a = enroll(f, "omarchy", "linux");
  enroll(f, "mini", "linux");
  await bootstrap(f);
  let rec = reconciliation(f.c);
  assert.deepEqual(rec.map((x) => [x.device, x.desired, x.state]), [["mini", 1, "pending"], ["omarchy", 1, "pending"]]);
  const out = f.c.sync(a, { last_applied: null });
  assert.ok(out.snapshot);
  rec = reconciliation(f.c);
  assert.equal(rec.find((x) => x.device === "omarchy")!.state, "pending", "delivered is not applied");
  f.c.sync(a, { last_applied: 1, receipts: [{ revision: 1, state: "applied" }] });
  f.clock.t += 11 * 60_000;
  rec = reconciliation(f.c);
  assert.equal(rec.find((x) => x.device === "omarchy")!.state, "current");
  assert.equal(rec.find((x) => x.device === "mini")!.state, "stale", "silent past the bound: stale, not green");
});

test("staged rollout: a revision reaches only opened stages; advancing needs every opened device to acknowledge", async () => {
  const f = fixture();
  const a = enroll(f, "canary", "linux");
  const b = enroll(f, "fleet1", "linux");
  await bootstrap(f);
  for (const d of [a, b]) {
    f.c.sync(d, { last_applied: null });
    f.c.sync(d, { last_applied: 1, receipts: [{ revision: 1, state: "applied" }] });
  }
  await publish(f, HOME + CURL_RULE.replace("curl-allow-example", "rule-two"));
  const owner = f.c.authenticate(f.ownerToken)!;
  createRollout(f.c, owner, { revision: 2, stages: [{ name: "canary", devices: ["canary"] }, { name: "rest", devices: ["fleet1"] }] });
  assert.equal((f.c.sync(b, { last_applied: 1 }).snapshot as unknown), null, "fleet1 is not released yet");
  const sa = f.c.sync(a, { last_applied: 1 }).snapshot as { payload: string } | null;
  assert.ok(sa, "canary receives revision 2");
  assert.throws(() => advanceRollout(f.c, owner, 2), /canary is pending/);
  f.c.sync(a, { last_applied: 2, receipts: [{ revision: 2, state: "applied" }] });
  const st = advanceRollout(f.c, owner, 2);
  assert.equal(st.opened, 2);
  assert.ok(f.c.sync(b, { last_applied: 1 }).snapshot, "stage 2 opened: fleet1 receives revision 2");
  assert.equal(rolloutStatus(f.c, 2).devices.find((x) => x.device === "fleet1")!.state, "pending");
  assert.throws(() => createRollout(f.c, owner, { revision: 2, stages: [{ name: "x", devices: ["canary"] }] }), /UNIQUE|already/);
});

test("offline local change: no last-writer-wins in either direction; the owner decides", async () => {
  const f = fixture();
  const a = enroll(f, "laptop", "linux");
  await bootstrap(f);
  f.c.sync(a, { last_applied: null });
  f.c.sync(a, { last_applied: 1, receipts: [{ revision: 1, state: "applied" }] });
  await publish(f, HOME + CURL_RULE); // a newer fleet revision exists
  const digest = "sha256:" + "ab".repeat(32);
  const r = f.c.sync(a, { last_applied: 1, local_change: { revision: 1, digest, broadening: true, authorized_by: "local-owner-key" } });
  assert.equal(r.snapshot, null, "the fleet revision is held instead of overwriting the device's local change");
  assert.match(String(r.held), /waits for the owner/);
  assert.equal(reconciliation(f.c)[0]!.state, "held");
  const owner = f.c.authenticate(f.ownerToken)!;
  assert.throws(() => resolveLocalChange(f.c, owner, "laptop", "newest-wins"), /resolution must be/);
  const viewer = f.c.authenticate(f.c.createToken("v", "viewer").token)!;
  assert.throws(() => resolveLocalChange(f.c, viewer, "laptop", "apply_fleet"), /owner/i);
  resolveLocalChange(f.c, owner, "laptop", "apply_fleet");
  assert.ok(f.c.sync(a, { last_applied: 1 }).snapshot, "after the owner's decision the fleet revision is delivered");
});

test("revocation and stale approvals: a revoked device cannot sync; an approval prepared against an old revision is refused", async () => {
  const f = fixture();
  enroll(f, "old", "linux");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const p1 = (await f.c.propose(owner, HOME + CURL_RULE, "a")) as { id: string; authorization_digest: string };
  const p2 = (await f.c.propose(owner, HOME + CURL_RULE.replace("curl-allow-example", "other"), "b")) as { id: string; authorization_digest: string };
  await f.c.approve(owner, p1.id, authorize(f.owner, p1.id, p1.authorization_digest));
  await assert.rejects(() => f.c.approve(owner, p2.id, authorize(f.owner, p2.id, p2.authorization_digest)), /prepared against revision 1/);
  f.c.revokeDevice(owner, "old");
  assert.throws(() => f.c.authenticateDevice("POST", "/v1/device/sync", { "x-moat-device": "old", "x-moat-ts": at(f), "x-moat-nonce": "n".repeat(20), "x-moat-sig": "x" }, "{}"), /revoked/);
  assert.equal(reconciliation(f.c).length, 0, "revoked devices leave reconciliation");
});
