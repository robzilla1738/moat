/**
 * Lane A's W05/W06 spool events (linux/moatd/src/spool.rs) and coverage labels, as the controller ingests them:
 * stream_terminated (evidence, no alarm), proxy_limit (refused, never bypassed), activation_recovery,
 * session_not_adopted, and coverage recovery-required / rollback-pending (never shown as healthy).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fixture } from "./helpers.ts";
import { enroll } from "./w12-helpers.ts";

const at = (f: { clock: { t: number } }) => new Date(f.clock.t).toISOString();

test("W05/W06 events: each is recorded; the ones that need the owner raise incidents; labels reach device state", () => {
  const f = fixture();
  const d = enroll(f, "omarchy", "linux");
  f.c.sync(d, {
    events: [
      { seq: 1, at: at(f), event: { type: "session_started", session_id: "s1", profile: "coding-session", cgroup: "moat.slice/s1", uid: 1000, root_pid: 10, root_start: 1, boundary: "linux_cgroup" } },
      { seq: 2, at: at(f), event: { type: "stream_terminated", session_id: "s1", stream: 7, destination: "140.82.112.6:443", hostname: "github.com", admitted_by: "coding-allow-github", reason: "no longer allowed by revision 3" } },
      { seq: 3, at: at(f), event: { type: "proxy_limit", session_id: "s1", resource: "connections", limit: 512 } },
      { seq: 4, at: at(f), event: { type: "session_not_adopted", session_id: "s1", profile: "coding-session", reason: "daemon restarted; session stopped with cgroup.kill" } },
      { seq: 5, at: at(f), event: { type: "activation_recovery", phase: "restored", active_revision: 2, detail: "interrupted activation rolled back to revision 2" } },
    ],
  });
  const inc = f.c.incidents() as { kind: string; reason: string; urgency: string; session_id: string | null }[];
  const kinds = inc.map((i) => i.kind).sort();
  assert.deepEqual(kinds, ["proxy_limit", "session_not_adopted"], "stream_terminated and a restored activation are evidence, not alarms");
  assert.match(inc.find((i) => i.kind === "proxy_limit")!.reason, /refused, not bypassed/);
  const sess = f.c.sessions("omarchy") as { id: string; state: string }[];
  assert.equal(sess.find((s) => s.id === "s1")!.state, "ended", "a session that was not adopted is not shown as running");
  const kindsRecorded = (f.c.flows.db.prepare("SELECT kind, detail FROM flows WHERE device_id = 'omarchy' ORDER BY seq").all() as { kind: string; detail: string | null }[]).map((r) => r.kind);
  assert.deepEqual(kindsRecorded, ["session", "stream_terminated", "proxy_limit", "session_not_adopted", "activation_recovery"]);

  // recovery_required phase sets the coverage label and raises a high incident
  f.c.sync(d, { events: [{ seq: 6, at: at(f), event: { type: "activation_recovery", phase: "recovery_required", detail: "corrupt journal kept as activation.json.corrupt" } }] });
  let dev = (f.c.devices() as { id: string; coverage: string; effective_coverage: string }[]).find((x) => x.id === "omarchy")!;
  assert.equal(dev.coverage, "recovery-required");
  assert.equal(dev.effective_coverage, "recovery-required");
  assert.ok((f.c.incidents() as { kind: string; urgency: string }[]).some((i) => i.kind === "recovery_required" && i.urgency === "high"));

  // rollback-pending via coverage_changed
  f.c.sync(d, { events: [{ seq: 7, at: at(f), event: { type: "coverage_changed", level: "rollback-pending", detail: "fallback could not be reinstalled" } }] });
  dev = (f.c.devices() as { id: string; coverage: string }[]).find((x) => x.id === "omarchy")! as never;
  assert.equal(dev.coverage, "rollback-pending");
  assert.ok((f.c.incidents() as { kind: string }[]).some((i) => i.kind === "rollback_pending"));
});
