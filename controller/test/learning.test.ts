/**
 * W14: bounded capture, immutable reviewed baselines, candidate diffs and drift review, with the MASTER_ROADMAP §9.4
 * poisoning cases; three maintained workflow packs; acknowledge/mute never allow.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { authorize, bootstrap, fixture, ROOT, type Fixture } from "./helpers.ts";
import { enroll, flow } from "./w12-helpers.ts";
import { approveCandidate, baseline, baselineRules, closeCapture, discardCandidate, driftReview, importCandidate, isMuted, learningOverview, muteIncident, permissionDiff, proposeBaseline, retireBaseline, startCapture } from "../src/learning.ts";
import { loadPacks, moduleDestinations, packDelta, packProblems, packRules, proposePack } from "../src/packs.ts";

function setup() {
  const f = fixture("Tue 2026-10-27 9:00 AM CDT (UTC-05:00)");
  const d = enroll(f, "omarchy", "linux");
  const owner = f.c.authenticate(f.ownerToken)!;
  return { f, d, owner };
}

function capture(f: Fixture, owner: ReturnType<Fixture["c"]["authenticate"]> & object, hours = 1) {
  return startCapture(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", workflow: "npm install", network_context: "home LAN", hours });
}

test("capture is bounded and identity-bound; nothing is accepted by default; a malicious connection and repetition confer no trust", () => {
  const { f, d, owner } = setup();
  assert.throws(() => startCapture(f.c, owner, { device_id: "omarchy", exe: "curl", workflow: "x", network_context: "y" }), /exact executable/);
  assert.throws(() => startCapture(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", workflow: "", network_context: "y" }), /name the workflow/);
  assert.throws(() => capture(f, owner, 24), /at most 8 hours/);
  const cap = capture(f, owner);
  f.clock.t += 60_000;
  const repeated = Array.from({ length: 200 }, () => flow(f, { host: "registry.npmjs.org", device: "omarchy" }));
  f.c.sync(d, { events: [...repeated, flow(f, { host: "evil.example", device: "omarchy" }), flow(f, { exe: "/tmp/curl", host: "other.example", device: "omarchy" })] });
  f.clock.t += 60_000;
  const cand = closeCapture(f.c, owner, cap.id);
  assert.deepEqual(cand.entries.map((e) => e.destination), ["evil.example", "registry.npmjs.org"], "only the captured identity; exact destinations");
  assert.ok(cand.entries.every((e) => e.status === "proposed"), "occurrence never changes status");
  assert.equal(cand.entries.find((e) => e.destination === "registry.npmjs.org")!.occurrences, 200, "repetition is shown as a count, nothing more");
  assert.throws(() => approveCandidate(f.c, owner, cand.id as string, {}), /nothing is accepted by default/);
  const npm = cand.entries.findIndex((e) => e.destination === "registry.npmjs.org");
  const b = approveCandidate(f.c, owner, cand.id as string, { accept: [npm], acknowledge_incomplete: true });
  assert.deepEqual(b.entries.map((e) => e.destination), ["registry.npmjs.org"], "the malicious connection seen during capture is not in the baseline");
});

test("missing events or uncertain identity prevent a complete claim; approval needs explicit acknowledgement", () => {
  const { f, d, owner } = setup();
  const cap = capture(f, owner);
  f.clock.t += 60_000;
  f.c.sync(d, { events: [flow(f, { host: "a.example", device: "omarchy" }), flow(f, { exe: null, host: "b.example", device: "omarchy" })] });
  f.c.sync(d, { events: [{ seq: 9999, at: new Date(f.clock.t).toISOString(), event: { type: "gap", from: 5000, to: 9998, reason: "spool full" } }] });
  f.clock.t += 60_000;
  const cand = closeCapture(f.c, owner, cap.id);
  assert.equal(cand.completeness, "incomplete");
  assert.ok(cand.incomplete_reasons.some((r) => /no executable identity/.test(r)));
  assert.ok(cand.incomplete_reasons.some((r) => /lost/.test(r)));
  assert.throws(() => approveCandidate(f.c, owner, cand.id, { accept: [0] }), /evidence is incomplete/);
});

test("baselines are immutable; drift creates a new candidate; new hosts are never hidden by a covering group; identity changes stay visible; unused entries get a seasonal caveat", () => {
  const { f, d, owner } = setup();
  const cap = capture(f, owner);
  f.clock.t += 60_000;
  f.c.sync(d, { events: [flow(f, { host: "s3.amazonaws.com", device: "omarchy" })] });
  f.clock.t += 60_000;
  const cand = closeCapture(f.c, owner, cap.id);
  const b = approveCandidate(f.c, owner, cand.id, { accept: [0], acknowledge_incomplete: true });
  assert.throws(() => f.c.db.prepare("UPDATE baselines SET entries = '[]' WHERE id = ?").run(b.id), /immutable/);
  assert.throws(() => f.c.db.prepare("DELETE FROM baselines WHERE id = ?").run(b.id), /immutable/);
  f.clock.t += 31 * 86400_000;
  f.c.sync(d, { events: [flow(f, { host: "exfil-bucket.s3.amazonaws.com", device: "omarchy" }), flow(f, { signer: "NEWTEAM", host: "s3.amazonaws.com", device: "omarchy" })] });
  const drift = driftReview(f.c, owner, b.id) as { drift: boolean; candidate: { entries: { destination: string }[]; identity_changes: { signer: string | null }[]; removal_proposals: { destination: string; caveat: string }[]; kind: string } };
  assert.equal(drift.drift, true);
  assert.equal(drift.candidate.kind, "drift");
  assert.deepEqual(drift.candidate.entries.map((e) => e.destination), ["exfil-bucket.s3.amazonaws.com"], "a new host under an already-reviewed provider is listed on its own");
  assert.ok(drift.candidate.identity_changes.some((x) => x.signer === "NEWTEAM"), "a signing change remains visible");
  assert.ok(drift.candidate.removal_proposals.some((x) => x.destination === "s3.amazonaws.com" && /seasonal/.test(x.caveat)), "unused 30+ days: proposed for removal with a caveat");
  assert.deepEqual(baseline(f.c, b.id).entries.map((e) => e.destination), ["s3.amazonaws.com"], "the approved baseline did not change");
  retireBaseline(f.c, owner, b.id, "replaced");
  assert.throws(() => driftReview(f.c, owner, b.id), /retired/);
});

test("imported baselines keep source and compatibility assumptions; wildcards and missing assumptions are refused", () => {
  const { f, owner } = setup();
  assert.throws(() => importCandidate(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", entries: [{ destination: "a.example" }], assumptions: { app_version: "8", platform: "linux" } }), /name its source/);
  assert.throws(() => importCandidate(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", entries: [{ destination: "a.example" }], source: "x" }), /compatibility assumptions/);
  assert.throws(() => importCandidate(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", entries: [{ destination: "*.example" }], source: "x", assumptions: { app_version: "8", platform: "linux" } }), /no wildcards/);
  const c = importCandidate(f.c, owner, { device_id: "omarchy", exe: "/usr/bin/curl", entries: [{ destination: "a.example", port: 443, transport: "tcp" }], source: "github.com/someone/baselines@abc", assumptions: { app_version: "curl 8.5", platform: "linux" } });
  assert.equal(c.completeness, "incomplete", "imported: not observed here");
  const b = approveCandidate(f.c, owner, c.id, { accept: [0], acknowledge_incomplete: true });
  assert.equal(b.source, "github.com/someone/baselines@abc");
  assert.deepEqual(b.assumptions, { app_version: "curl 8.5", platform: "linux" });
});

test("enforcing a baseline is a normal broadening proposal: the owner key is required; existing denies keep precedence", async () => {
  const { f, d, owner } = setup();
  await bootstrap(f);
  const cap = capture(f, owner);
  f.clock.t += 60_000;
  f.c.sync(d, { events: [flow(f, { host: "registry.npmjs.org", port: 443, device: "omarchy" })] });
  f.clock.t += 60_000;
  const cand = closeCapture(f.c, owner, cap.id);
  const b = approveCandidate(f.c, owner, cand.id, { accept: [0], acknowledge_incomplete: true });
  assert.match(baselineRules({ id: b.id, exe: b.exe, signer: null, entries: b.entries }), /executable = "\/usr\/bin\/curl"/);
  const prop = (await proposeBaseline(f.c, owner, b.id)) as { id: string; broadening: boolean; authorization_digest: string };
  assert.equal(prop.broadening, true);
  await assert.rejects(() => f.c.approve(owner, prop.id, null), /owner/i);
  const ok = await f.c.approve(owner, prop.id, authorize(f.owner, prop.id, prop.authorization_digest));
  assert.equal((ok as { revision: number }).revision, 2);
});

test("three maintained packs: modules carry rationale, capabilities, versions, breakage, provenance and a test recipe; enabling is owner-authorized", async () => {
  const packs = loadPacks(join(ROOT, "packs/workflows"));
  assert.deepEqual(packs.map((p) => p.id), ["coding", "home-services", "local-inference"]);
  for (const p of packs) assert.deepEqual(packProblems(p), [], p.id);
  const f = fixture();
  await bootstrap(f);
  for (const p of packs) {
    const v = await f.moatctl.validate(f.c.currentRevision()!.source + packRules(p, p.modules.map((m) => m.id)));
    assert.ok(v.ok, `${p.id}: ${v.errors.join("; ")}`);
  }
  const owner = f.c.authenticate(f.ownerToken)!;
  await assert.rejects(() => proposePack(f.c, owner, packs, { pack: "coding", modules: [] }), /nothing is enabled by default/);
  const r = await proposePack(f.c, owner, packs, { pack: "coding", modules: ["repository", "packages"] });
  assert.deepEqual(r.omitted_modules.map((m) => m.module), ["model-api"]);
  assert.match(r.note, /estimate/);
  const prop = r.proposal as { id: string; broadening: boolean };
  assert.equal(prop.broadening, true, "pack broadening");
  await assert.rejects(() => f.c.approve(owner, prop.id, null), /owner/i, "signed pack data is not owner consent");
  assert.ok(packProblems({ ...packs[0]!, modules: [{ ...packs[0]!.modules[0]!, test_recipe: [] }] }).some((x) => /test_recipe/.test(x)));
});

test("acknowledge means seen and mute means no notifications: neither allows anything", async () => {
  const { f, d, owner } = setup();
  await bootstrap(f);
  f.c.notifier.addDestination({ name: "phone", kind: "ntfy", url: "https://ntfy.example/x", min_urgency: "low" });
  f.c.sync(d, { events: [flow(f, { host: "blocked.example", verdict: "deny", rule: "x", device: "omarchy" })] });
  const inc = (f.c.incidents() as { id: string; dedup_key?: string; revision: number }[])[0]!;
  const outboxBefore = (f.c.db.prepare("SELECT COUNT(*) AS n FROM notify_outbox").get() as { n: number }).n;
  const policyBefore = f.c.currentRevision()!.revision;
  muteIncident(f.c, owner, inc.id, 60);
  f.c.acknowledge(owner, inc.id, inc.revision);
  f.c.sync(d, { events: [flow(f, { host: "blocked.example", verdict: "deny", rule: "x", device: "omarchy" })] });
  assert.equal((f.c.db.prepare("SELECT COUNT(*) AS n FROM notify_outbox").get() as { n: number }).n, outboxBefore, "muted: no new notification");
  const after = (f.c.incidents() as { id: string; state: string; occurrences: number }[]).find((i) => i.id === inc.id)!;
  assert.equal(after.state, "open", "a new occurrence reopens it: still visible");
  assert.equal(after.occurrences, 2);
  assert.equal(f.c.currentRevision()!.revision, policyBefore, "no policy change");
  assert.equal((f.c.grants() as unknown[]).length, 0, "no grant");
  const key = (f.c.db.prepare("SELECT dedup_key FROM incidents WHERE id = ?").get(inc.id) as { dedup_key: string }).dedup_key;
  assert.equal(isMuted(f.c, key), true);
  f.clock.t += 61 * 60_000;
  assert.equal(isMuted(f.c, key), false, "mutes expire");
});

test("review surfaces: the queue shows each candidate's permission diff and evidence; drift lands in its own queue; viewers read, only owners act", () => {
  const { f, d, owner } = setup();
  const viewer = f.c.authenticate(f.c.createToken("phone", "viewer").token)!;
  const cap = capture(f, owner);
  let o = learningOverview(f.c);
  assert.equal(o.captures[0]!.state, "capturing");
  f.clock.t += 60_000;
  f.c.sync(d, { events: [flow(f, { host: "registry.npmjs.org", device: "omarchy" }), flow(f, { host: "evil.example", verdict: "deny", rule: "x", device: "omarchy" }), flow(f, { exe: null, host: "who.example", device: "omarchy" })] });
  f.clock.t += 60_000;
  const cand = closeCapture(f.c, owner, cap.id);
  o = learningOverview(f.c);
  assert.equal(o.captures[0]!.state, "closed");
  assert.equal(o.captures[0]!.candidate_id, cand.id);
  const q = o.review_queue.find((x) => x.id === cand.id)!;
  assert.equal(q.permission_diff.baseline_id, null, "first capture: nothing reviewed before");
  assert.equal(q.permission_diff.adds, 2, "every exact destination of the captured identity would broaden");
  assert.ok(q.permission_diff.rows.find((r) => r.destination === "evil.example")!.denied_only, "refused-only entries are marked");
  assert.ok(q.incomplete_reasons.some((r) => /no executable identity/.test(r)), "unknown identity is a visible gap");
  assert.equal(o.drift_queue.length, 0);
  assert.throws(() => discardCandidate(f.c, viewer, cand.id), /owner/i, "a viewer cannot act on the queue");
  assert.throws(() => approveCandidate(f.c, viewer, cand.id, { accept: [0], acknowledge_incomplete: true }), /owner/i, "a viewer cannot accept a baseline");
  const npm = cand.entries.findIndex((e) => e.destination === "registry.npmjs.org");
  const b = approveCandidate(f.c, owner, cand.id, { accept: [npm], acknowledge_incomplete: true });
  o = learningOverview(f.c);
  assert.equal(o.review_queue.length, 0);
  assert.deepEqual(o.baselines.map((x) => x.id), [b.id]);
  f.clock.t += 60_000;
  f.c.sync(d, { events: [flow(f, { host: "registry.npmjs.org", device: "omarchy" }), flow(f, { host: "cdn.npmjs.example", device: "omarchy" })] });
  const drift = driftReview(f.c, owner, b.id) as { candidate: { id: string } };
  o = learningOverview(f.c);
  const dq = o.drift_queue.find((x) => x.id === drift.candidate.id)!;
  assert.ok(dq, "drift is a separate queue");
  assert.equal(dq.permission_diff.baseline_id, b.id);
  assert.deepEqual(dq.permission_diff.rows.map((r) => [r.destination, r.change]), [["cdn.npmjs.example", "adds"]], "only what the baseline does not cover is proposed");
  discardCandidate(f.c, owner, drift.candidate.id);
  assert.equal(learningOverview(f.c).drift_queue.length, 0, "more evidence needed: discarded, nothing accepted");
  assert.deepEqual(baseline(f.c, b.id).entries.map((e) => e.destination), ["registry.npmjs.org"], "the baseline did not change");
  assert.equal(permissionDiff(f.c, { ...dq, entries: [] }).adds, 0);
});

test("pack browser: each module's effective delta against the current policy and the devices; unsupported cells are listed, not hidden", async () => {
  const packs = loadPacks(join(ROOT, "packs/workflows"));
  const { f, owner } = setup();
  enroll(f, "mbp", "macos");
  await bootstrap(f);
  const coding = packs.find((p) => p.id === "coding")!;
  assert.deepEqual(moduleDestinations(coding.modules[0]!).hosts, ["github.com", "api.github.com", "codeload.github.com"]);
  const dl = packDelta(f.c, coding);
  assert.deepEqual(dl.devices.map((x) => x.id), ["mbp", "omarchy"]);
  const repo = dl.modules.find((m) => m.id === "repository")!;
  assert.equal(repo.enabled, false);
  const linux = repo.cells.find((c) => c.device_id === "omarchy")!;
  const mac = repo.cells.find((c) => c.device_id === "mbp")!;
  assert.equal(linux.support, "unknown", "omarchy did not advertise session_hostname_proxy: unknown is not supported");
  assert.ok(linux.missing.some((m) => m.capability === "session_hostname_proxy"));
  assert.equal(linux.takes_effect, false);
  assert.equal(mac.takes_effect, false);
  assert.equal(repo.unsupported_cells, 2);
  assert.ok(dl.effective.unsupported_cells >= 2);
  const r = await proposePack(f.c, owner, packs, { pack: "coding", modules: ["repository"] });
  const prop = r.proposal as { id: string; authorization_digest: string };
  await f.c.approve(owner, prop.id, authorize(f.owner, prop.id, prop.authorization_digest));
  const after = packDelta(f.c, coding).modules.find((m) => m.id === "repository")!;
  assert.equal(after.enabled, true);
  assert.deepEqual(after.newly_allowed, [], "already enabled: no new destinations");
});

test("the macOS app bundles exactly the maintained packs (macos/MoatKit/Sources/MoatKit/Packs mirrors packs/workflows)", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const src = join(ROOT, "packs/workflows");
  const mac = join(ROOT, "macos/MoatKit/Sources/MoatKit/Packs");
  assert.deepEqual(readdirSync(mac).sort(), readdirSync(src).filter((f) => f.endsWith(".json")).sort());
  for (const f of readdirSync(src).filter((x) => x.endsWith(".json"))) assert.equal(readFileSync(join(mac, f), "utf8"), readFileSync(join(src, f), "utf8"), `${f}: copy packs/workflows/${f} into the macOS bundle`);
});
