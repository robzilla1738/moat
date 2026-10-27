/**
 * Adversarial matrix "Notification floods" (MASTER_ROADMAP §9.4, §15.2): notifications are grouped by stable subject,
 * destination and reason; one actionable notification per unchanged incident; a burst of distinct destinations from
 * one subject collapses into one summary per window; acknowledge and mute never allow anything.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { bootstrap, fixture } from "./helpers.ts";
import { enroll, flow } from "./w12-helpers.ts";
import { FLOOD_INDIVIDUAL, FLOOD_WINDOW_MS } from "../src/controller.ts";
import { muteIncident } from "../src/learning.ts";

async function setup() {
  const f = fixture();
  const d = enroll(f, "omarchy", "linux");
  await bootstrap(f);
  f.c.notifier.addDestination({ name: "phone", kind: "ntfy", url: "https://ntfy.example/x", min_urgency: "low" });
  const owner = f.c.authenticate(f.ownerToken)!;
  const outbox = () => (f.c.db.prepare("SELECT COUNT(*) AS n FROM notify_outbox").get() as { n: number }).n;
  const blocked = (host: string, revision = 1) => flow(f, { host, verdict: "deny", rule: "deny-x", device: "omarchy", revision });
  return { f, d, owner, outbox, blocked };
}

test("a repeated block is one incident with a count and duration, and one notification", async () => {
  const { f, d, outbox, blocked } = await setup();
  const before = outbox();
  for (let i = 0; i < 5; i++) {
    f.c.sync(d, { events: Array.from({ length: 10 }, () => blocked("blocked.example")) });
    f.clock.t += 30_000;
  }
  const incs = (f.c.incidents() as { kind: string; occurrences: number; first_at: string; last_at: string }[]).filter((i) => i.kind === "blocked_connection");
  assert.equal(incs.length, 1, "grouped by subject, destination and reason");
  assert.equal(incs[0]!.occurrences, 50);
  assert.ok(incs[0]!.last_at > incs[0]!.first_at, "duration is visible");
  assert.equal(outbox() - before, 1, "one notification");
});

test("an unchanged incident does not notify again after acknowledgement or keep-blocked; a changed one does once", async () => {
  const { f, d, owner, outbox, blocked } = await setup();
  f.c.sync(d, { events: [blocked("blocked.example")] });
  const n1 = outbox();
  let inc = (f.c.incidents() as { id: string; revision: number }[])[0]!;
  const policy = f.c.currentRevision()!.revision;
  f.c.acknowledge(owner, inc.id, inc.revision);
  f.c.sync(d, { events: [blocked("blocked.example"), blocked("blocked.example")] });
  inc = (f.c.incidents() as { id: string; revision: number; state: string; occurrences: number }[])[0]! as never;
  assert.equal((inc as unknown as { state: string }).state, "open", "the recurrence is visible");
  assert.equal(outbox(), n1, "acknowledged and unchanged: no second notification");
  f.c.resolve(owner, inc.id, (f.c.incidents() as { revision: number }[])[0]!.revision);
  f.c.sync(d, { events: [blocked("blocked.example")] });
  assert.equal(outbox(), n1, "kept blocked and unchanged: no second notification");
  f.c.acknowledge(owner, inc.id, (f.c.incidents() as { revision: number }[])[0]!.revision);
  f.c.sync(d, { events: [blocked("blocked.example", 7)] });
  assert.equal(outbox(), n1 + 1, "recurring under a different policy revision is a change: one new notification");
  assert.equal(f.c.currentRevision()!.revision, policy, "acknowledging changed no policy");
  assert.equal((f.c.grants() as unknown[]).length, 0, "and created no grant");
});

test("a burst of distinct destinations from one subject: every incident listed, a few individual notifications, then one summary per window", async () => {
  const { f, d, outbox, blocked } = await setup();
  const before = outbox();
  f.c.sync(d, { events: Array.from({ length: 40 }, (_, i) => blocked(`scan-${i}.example`)) });
  const incs = (f.c.incidents() as { kind: string; state: string }[]).filter((i) => i.kind === "blocked_connection");
  assert.equal(incs.length, 40, "each distinct destination is its own incident and stays visible");
  assert.ok(incs.every((i) => i.state === "open"));
  assert.equal(outbox() - before, FLOOD_INDIVIDUAL + 1, "individual notifications up to the limit, then a single summary");
  const g = f.c.notificationGroups().find((x) => x.kind === "blocked_connection")!;
  assert.equal(g.raised, 40);
  assert.equal(g.notified_individually, FLOOD_INDIVIDUAL);
  assert.match(String(g.note), /grouped into one notification/);
  f.c.sync(d, { events: Array.from({ length: 10 }, (_, i) => blocked(`scan-more-${i}.example`)) });
  assert.equal(outbox() - before, FLOOD_INDIVIDUAL + 1, "still one summary in the same window");
  f.clock.t += FLOOD_WINDOW_MS;
  f.c.sync(d, { events: [blocked("next-window.example")] });
  assert.equal(outbox() - before, FLOOD_INDIVIDUAL + 2, "a new window notifies again");
  assert.equal((f.c.grants() as unknown[]).length, 0, "grouping notifications allows nothing");
});

test("mute suppresses notifications for one subject only, and never allows", async () => {
  const { f, d, owner, outbox, blocked } = await setup();
  f.c.sync(d, { events: [blocked("noisy.example")] });
  const inc = (f.c.incidents() as { id: string; revision: number }[])[0]!;
  muteIncident(f.c, owner, inc.id, 60);
  const n = outbox();
  f.c.resolve(owner, inc.id, inc.revision);
  f.c.sync(d, { events: [blocked("noisy.example", 9)] });
  assert.equal(outbox(), n, "muted: even a changed recurrence does not notify");
  f.c.sync(d, { events: [blocked("other.example")] });
  assert.equal(outbox(), n + 1, "another destination is another subject");
  assert.equal((f.c.grants() as unknown[]).length, 0);
  assert.equal(f.c.currentRevision()!.revision, 1, "no policy change");
});
