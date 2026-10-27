/**
 * W13 sync agent against Lane A's moatd outbox files (docs/fleet-sync.md, docs/platforms/linux.md "Fleet-sync outbox"):
 * the agent reads `spool/sync-state.json` (moat.spool_sync_state.v1) into the sync body and writes the controller's
 * contiguous acked_seq to `spool/acked`. Real controller over HTTP with the real signer and moatctl; the moatd side is
 * a state directory written in moatd's formats.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { startServer } from "../src/server.ts";
import { enroll, readSyncState, syncOnce, writeAck, type AgentFetch, type AgentState } from "../src/agent.ts";
import { reconciliation, resolveLocalChange } from "../src/fleet.ts";
import { authorize, bootstrap, fixture, HOME, type Fixture } from "./helpers.ts";
import { CURL_RULE } from "./w12-helpers.ts";

const DIGEST = "sha256:" + "cd".repeat(32);

function moatdDir() {
  const dir = mkdtempSync(join(tmpdir(), "moatd-sync-"));
  mkdirSync(join(dir, "spool"), { recursive: true });
  return dir;
}

/** Write records 1..n into a segment the way moatd does (one JSON line per record). */
function spoolRecords(dir: string, device: string, seqs: number[], segFirst = seqs[0]!) {
  const at = new Date().toISOString();
  const lines = seqs.map((seq) =>
    JSON.stringify({ seq, device_id: device, boot_id: "boot-1", at, event: { type: "flow", attempt: { id: `a${seq}`, device_id: device, app: { family: "curl", executable: "/usr/bin/curl" }, remote_ip: "203.0.113.9", remote_port: 443, transport: "tcp", at }, decision: { verdict: "deny", profile: "p", policy_revision: 1 } } }),
  );
  writeFileSync(join(dir, "spool", `seg-${String(segFirst).padStart(20, "0")}.jsonl`), lines.join("\n") + "\n");
}

function syncState(dir: string, s: { device: string; low: number; acked: number; next: number; local_change?: unknown }) {
  writeFileSync(join(dir, "spool", "sync-state.json"), JSON.stringify({ schema: "moat.spool_sync_state.v1", device_id: s.device, boot_id: "boot-1", spool_low_seq: s.low, acked_seq: s.acked, next_seq: s.next, local_change: s.local_change ?? null }, null, 2));
}

const ackFile = (dir: string) => (existsSync(join(dir, "spool", "acked")) ? readFileSync(join(dir, "spool", "acked"), "utf8") : null);

async function harness(): Promise<{ f: Fixture; base: string; fetchOk: AgentFetch; close: () => void; st: AgentState; down: { on: boolean } }> {
  const f = fixture(new Date().toISOString());
  const srv = startServer(f.c, { host: "127.0.0.1", port: 0 });
  await new Promise((r) => srv.once("listening", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const down = { on: false };
  const fetchOk: AgentFetch = (u, i) => {
    if (down.on) return Promise.reject(new Error("ECONNREFUSED (controller outage)"));
    f.clock.t = Date.now();
    return fetch(u, i) as never;
  };
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  const st = await enroll(base, code, "omarchy", "linux", fetchOk);
  return { f, base, fetchOk, close: () => srv.close(), st, down };
}

const flowCount = (f: Fixture) => (f.c.flows.db.prepare("SELECT COUNT(*) AS n FROM flows WHERE device_id = 'omarchy'").get() as { n: number }).n;
const gaps = (f: Fixture) => (f.c.incidents() as { kind: string }[]).filter((i) => i.kind === "telemetry_gap").length;

test("sync-state parsing: unknown schema, torn file, impossible numbers and bad digests are not believed", () => {
  const d = moatdDir();
  assert.equal(readSyncState(join(d, "spool")), null, "missing");
  writeFileSync(join(d, "spool", "sync-state.json"), "{\"schema\":\"moat.spool_sync_state.v1\",");
  assert.equal(readSyncState(join(d, "spool")), null, "torn");
  syncState(d, { device: "omarchy", low: 1, acked: 0, next: 4 });
  assert.deepEqual(readSyncState(join(d, "spool"))!.spool_low_seq, 1);
  writeFileSync(join(d, "spool", "sync-state.json"), JSON.stringify({ schema: "moat.spool_sync_state.v2", device_id: "omarchy", spool_low_seq: 1, acked_seq: 0, next_seq: 4 }));
  assert.equal(readSyncState(join(d, "spool")), null, "a newer schema is not guessed at");
  syncState(d, { device: "omarchy", low: 9, acked: 0, next: 4 });
  assert.equal(readSyncState(join(d, "spool")), null, "low beyond next");
  syncState(d, { device: "omarchy", low: 1, acked: 7, next: 4 });
  assert.equal(readSyncState(join(d, "spool")), null, "acked beyond the last written sequence");
  syncState(d, { device: "omarchy", low: 1, acked: 0, next: 4, local_change: { revision: 3, digest: "md5:x", broadening: true, authorized_by: "k" } });
  assert.equal(readSyncState(join(d, "spool")), null, "local_change digest must be sha256");
  // writeAck: never lowers, never beyond next_seq-1
  syncState(d, { device: "omarchy", low: 1, acked: 0, next: 4 });
  const s = readSyncState(join(d, "spool"));
  assert.deepEqual(writeAck(join(d, "spool"), 3, s), { written: 3 });
  assert.match(String(writeAck(join(d, "spool"), 2, s).reason), /never moves backwards/);
  assert.equal(ackFile(d), "3");
  assert.match(String(writeAck(join(d, "spool"), 4, s).reason), /beyond the last sequence written \(3\)/);
  assert.equal(ackFile(d), "3");
  rmSync(d, { recursive: true, force: true });
});

test("agent: duplicate, reorder, outage and reconnect against moatd's sync-state.json and spool/acked", async () => {
  const h = await harness();
  try {
    const d = moatdDir();
    // moatd wrote 1,2 and 4 so far in this view (3 is in a segment the agent has not seen yet: a reorder)
    spoolRecords(d, "omarchy", [1, 2]);
    spoolRecords(d, "omarchy", [4], 4);
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 5 });
    let r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.uploaded, 3);
    assert.equal(r.acked_seq, 2, "3 is missing: contiguous high-water stops at 2");
    assert.deepEqual(r.pending_ranges, [[3, 3]], "a hole is pending, not loss");
    assert.equal(ackFile(d), "2", "spool/acked carries the contiguous ack for moatd");
    assert.equal(gaps(h.f), 0);
    // reorder: 3 shows up after 4; moatd accepted ack 2
    spoolRecords(d, "omarchy", [3], 3);
    syncState(d, { device: "omarchy", low: 1, acked: 2, next: 5 });
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.uploaded, 2, "everything above the ack is resent (3 and 4)");
    assert.equal(r.acked_seq, 4);
    assert.equal(ackFile(d), "4");
    assert.equal(flowCount(h.f), 4, "the duplicate 4 is stored once");
    // duplicate: the same round again changes nothing
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.uploaded, 0);
    h.st.cursor = 0; // a resend of everything (e.g. agent state restored from an old backup)
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 5 });
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.uploaded, 4);
    assert.equal(flowCount(h.f), 4, "resent records are not new flows");
    const occ = (h.f.c.incidents() as { occurrences: number; destination: string }[]).find((i) => i.destination === "203.0.113.9")!.occurrences;
    assert.equal(occ, 4, "nor new incident occurrences");
    assert.equal(ackFile(d), "4", "never lowered");
    // outage: the controller is unreachable; moatd keeps spooling, nothing is acknowledged
    h.down.on = true;
    spoolRecords(d, "omarchy", [5, 6, 7], 5);
    syncState(d, { device: "omarchy", low: 1, acked: 4, next: 8 });
    await assert.rejects(syncOnce(h.st, d, h.fetchOk), /ECONNREFUSED/);
    assert.equal(ackFile(d), "4", "an outage acknowledges nothing");
    // meanwhile moatd evicted 5 and 6 under quota and wrote a gap record for them (seq 8)
    rmSync(join(d, "spool", `seg-${String(5).padStart(20, "0")}.jsonl`));
    spoolRecords(d, "omarchy", [7], 7);
    writeFileSync(join(d, "spool", `seg-${String(8).padStart(20, "0")}.jsonl`), JSON.stringify({ seq: 8, device_id: "omarchy", boot_id: "boot-1", at: new Date().toISOString(), event: { type: "gap", from: 5, to: 6, reason: "evicted before acknowledgement: spool disk quota" } }) + "\n");
    syncState(d, { device: "omarchy", low: 7, acked: 4, next: 9 });
    // reconnect
    h.down.on = false;
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.acked_seq, 8, "5..6 declared lost by spool_low_seq and the gap record; 7..8 stored");
    assert.equal(ackFile(d), "8");
    assert.equal(gaps(h.f), 1, "the loss is a visible telemetry gap");
    const seqs = (h.f.c.flows.db.prepare("SELECT seq FROM flows WHERE device_id = 'omarchy' ORDER BY seq").all() as { seq: number }[]).map((x) => x.seq);
    assert.ok(seqs.includes(7) && !seqs.includes(5) && !seqs.includes(6), "5 and 6 are not invented");
    rmSync(d, { recursive: true, force: true });
  } finally {
    h.close();
  }
});

test("agent: a controller claiming more than moatd wrote is not believed; a lower ack makes the agent resend, never lowers spool/acked", async () => {
  const h = await harness();
  try {
    const d = moatdDir();
    spoolRecords(d, "omarchy", [1, 2, 3]);
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 4 });
    let r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.acked_seq, 3);
    // Another moatd state (e.g. the spool was wiped and next_seq restarted) where the controller already has 3:
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 2 });
    rmSync(join(d, "spool", "acked"));
    spoolRecords(d, "omarchy", [1]);
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.ack_written, null);
    assert.match(String(r.ack_refused), /beyond the last sequence written \(1\)/);
    assert.equal(ackFile(d), null, "nothing written that moatd would refuse");
    // spool belonging to another device is refused outright
    syncState(d, { device: "mini", low: 1, acked: 0, next: 2 });
    await assert.rejects(syncOnce(h.st, d, h.fetchOk), /belongs to device mini/);
    rmSync(d, { recursive: true, force: true });
  } finally {
    h.close();
  }
});

test("agent: moatd's local_change holds the fleet revision; a stale approval is refused; the owner decides", async () => {
  const h = await harness();
  try {
    const { f } = h;
    await bootstrap(f);
    const d = moatdDir();
    // receive and apply revision 1
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 1 });
    let r = await syncOnce(h.st, d, h.fetchOk);
    assert.ok(r.snapshot);
    spoolRecords(d, "omarchy", [1]);
    writeFileSync(join(d, "spool", `seg-${String(1).padStart(20, "0")}.jsonl`), JSON.stringify({ seq: 1, device_id: "omarchy", boot_id: "boot-1", at: new Date().toISOString(), event: { type: "policy_applied", revision: 1 } }) + "\n");
    syncState(d, { device: "omarchy", low: 1, acked: 0, next: 2 });
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(h.st.last_applied, 1);
    // two proposals prepared against revision 1; the first is approved, the second is now stale
    const owner = f.c.authenticate(f.ownerToken)!;
    const p1 = (await f.c.propose(owner, HOME + CURL_RULE, "a")) as { id: string; authorization_digest: string };
    const p2 = (await f.c.propose(owner, HOME + CURL_RULE.replace("curl-allow-example", "other"), "b")) as { id: string; authorization_digest: string };
    // while offline, the owner changed policy locally on the device (moatd recorded it as a broadening local change)
    syncState(d, { device: "omarchy", low: 2, acked: 1, next: 2, local_change: { revision: 2, digest: DIGEST, broadening: true, authorized_by: "local-owner-key" } });
    await f.c.approve(owner, p1.id, authorize(f.owner, p1.id, p1.authorization_digest));
    await assert.rejects(() => f.c.approve(owner, p2.id, authorize(f.owner, p2.id, p2.authorization_digest)), /prepared against revision/, "stale approval refused");
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.snapshot, false, "the fleet revision does not overwrite the local change (no last-writer-wins)");
    assert.match(String(r.held), /waits for the owner/);
    assert.equal(reconciliation(f.c).find((x) => x.device === "omarchy")!.state, "held");
    // a repeated report of the same local change is idempotent
    await syncOnce(h.st, d, h.fetchOk);
    assert.equal((f.c.db.prepare("SELECT COUNT(*) AS n FROM local_changes WHERE device_id = 'omarchy'").get() as { n: number }).n, 1);
    resolveLocalChange(f.c, owner, "omarchy", "apply_fleet");
    syncState(d, { device: "omarchy", low: 2, acked: 1, next: 2 });
    r = await syncOnce(h.st, d, h.fetchOk);
    assert.equal(r.snapshot, true, "after the owner's decision the fleet revision is delivered");
    assert.equal(readdirSync(join(d, "inbox")).length, 2);
    rmSync(d, { recursive: true, force: true });
  } finally {
    h.close();
  }
});
