/**
 * W12 standalone read models: apps by executable identity, app detail (permissions / changes / activity / why),
 * "What changed?" and diagnostics. Real moatctl (normalize, explain), real flow store.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { appId, apps, appDetail, diagnostics, UNKNOWN_APP, whatChanged } from "../src/standalone.ts";
import { authorize, bootstrap, fixture, HOME, type Fixture } from "./helpers.ts";
import { CURL_RULE, enroll, flow, nextSeq } from "./w12-helpers.ts";

async function publish(f: Fixture, source: string, message: string) {
  const p = f.c.authenticate(f.ownerToken)!;
  const prop = (await f.c.propose(p, source, message)) as { id: string; authorization_digest: string };
  return f.c.approve(p, prop.id, authorize(f.owner, prop.id, prop.authorization_digest));
}

test("apps are executable identities: same family at another path or signer is a different app; unknown identity stays visible", async () => {
  const f = fixture();
  const d = enroll(f);
  f.c.sync(d, { events: [flow(f, { minutesAgo: 3000, host: "example.org" }), flow(f, { minutesAgo: 10, host: "new.example.net" }), flow(f, { exe: "/tmp/x/curl", minutesAgo: 5, host: "example.org" }), flow(f, { exe: null, minutesAgo: 1, host: "example.org" }), flow(f, { signer: "TEAM1", minutesAgo: 2 })] });
  const list = apps(f.c);
  const ids = list.map((a) => a.id);
  assert.equal(new Set(ids).size, 4, "/usr/bin/curl, /usr/bin/curl+TEAM1, /tmp/x/curl and unknown are four apps");
  assert.equal(list.at(-1)!.id, UNKNOWN_APP, "unknown identity is listed (last), never merged into curl");
  assert.equal(list.at(-1)!.identity, "unknown");
  const curl = list.find((a) => a.id === appId("/usr/bin/curl", null))!;
  assert.deepEqual(curl.devices, ["mbp"]);
  assert.equal(curl.destinations.find((x) => x.host === "new.example.net")!.new, true, "a destination first seen today on an older app is new");
  assert.equal(curl.destinations.find((x) => x.host === "example.org")!.new, false);
  const tmp = list.find((a) => a.exe === "/tmp/x/curl")!;
  assert.equal(tmp.destinations[0]!.new, false, "an app first seen today has no history: nothing is flagged new");
});

test("app detail: permissions name direct, inherited and session rules; changes come from revisions; why = recorded decision + core explanation now", async () => {
  const f = fixture();
  const d = enroll(f);
  await bootstrap(f);
  f.c.sync(d, { events: [flow(f, { host: "example.org", minutesAgo: 30, revision: 1, observed: true }), flow(f, { ip: "203.0.113.9", minutesAgo: 20, revision: 1, observed: true })] });
  f.clock.t += 60_000;
  await publish(f, HOME + CURL_RULE, "allow curl → example.org");
  const det = (await appDetail(f.c, appId("/usr/bin/curl", null)))!;
  assert.ok(det);
  assert.equal(det.policy_revision, 2);
  const direct = det.permissions.find((p) => p.rule === "curl-allow-example")!;
  assert.equal(direct.how, "direct");
  assert.equal(direct.action, "allow");
  assert.deepEqual(direct.devices, [{ device: "mbp", enforced: true, note: null }], "the macOS snapshot carries the per-app rule");
  assert.ok(!det.permissions.some((p) => p.rule === "safety-workloads-never-reach-controller"), "session-only rules are not shown for an app that never ran in a protected session");
  assert.ok(!det.permissions.some((p) => p.how === "direct" && p.rule.startsWith("coding-")), "rules for other subjects are not direct");
  assert.deepEqual(det.changes.map((c) => [c.revision, c.kind, c.rule]), [[2, "added", "curl-allow-example"]]);
  const why = det.why.find((w) => w.destination === "example.org")!;
  assert.equal(why.recorded.verdict, "observed", "the endpoint only observed it at revision 1 (a fact)");
  assert.equal(why.recorded.revision, 1);
  assert.equal((why.now as { verdict?: string; permitted_by_observation?: boolean }).permitted_by_observation, false, "the core says revision 2 allows it by an explicit rule now, not by observation");
  assert.match(JSON.stringify(why.now), /curl-allow-example/);
  assert.ok(det.notes.some((n) => /code-signing/.test(n)), "missing signer identity is stated");
  assert.equal(await appDetail(f.c, "app-0000000000000000"), null);
});

test("what changed: observed differences are separated from candidates, each candidate has a reversible test; gaps are shown", async () => {
  const f = fixture("Tue 2026-10-27 12:00 PM CDT (UTC-05:00)");
  const d = enroll(f);
  await bootstrap(f);
  // Working interval (2 hours ago): curl reaches example.org at revision 1.
  f.c.sync(d, { events: [flow(f, { host: "example.org", minutesAgo: 120, revision: 1 })] });
  f.clock.t += 0;
  await publish(f, HOME + CURL_RULE, "allow curl → example.org");
  // Failing interval: new signer identity, example.org denied at revision 2, and a lost event range.
  nextSeq(3); // the endpoint lost three events
  f.c.sync(d, { events: [flow(f, { host: "example.org", verdict: "deny", rule: "safety-example", revision: 2, minutesAgo: 5 }), flow(f, { signer: "TEAM9", host: "cdn.example.org", minutesAgo: 4, revision: 2 })] });
  const t = (m: number) => new Date(f.clock.t - m * 60_000).toISOString();
  const r = whatChanged(f.c, { device: "mbp", working: `${t(180)}/${t(60)}`, failing: `${t(30)}/${t(0)}` });
  const kinds = r.observed.map((o) => o.kind);
  assert.ok(kinds.includes("identity") && kinds.includes("policy") && kinds.includes("destination") && kinds.includes("telemetry"), JSON.stringify(kinds));
  assert.ok(r.candidates.length >= 3);
  for (const c of r.candidates) assert.equal(c.test.reversible, true);
  assert.ok(r.candidates.some((c) => c.test.action === "rollback_preview:1"), "policy candidate links to a rollback preview, not a rollback");
  assert.ok(r.candidates.some((c) => c.test.action === "plan_grant:example.org:443"), "blocked destination links to a reviewed plan");
  assert.match(r.disclaimer, /none is claimed as the cause/);
  assert.ok(r.not_compared.length > 0, "what is not compared is stated");
  assert.throws(() => whatChanged(f.c, { working: "nope", failing: `${t(30)}/${t(0)}` }), /working must be/);
});

test("diagnostics: versions, policy generation, evidence age, downgraded capabilities, spool high-water and gaps", async () => {
  const f = fixture();
  const d = enroll(f);
  await bootstrap(f);
  f.c.sync(d, { last_applied: 1, receipts: [{ revision: 1, state: "applied" }], events: [flow(f, {}), { seq: nextSeq(5), at: new Date(f.clock.t).toISOString(), event: { type: "coverage_changed", level: "enforced" } }] });
  f.clock.t += 15 * 60_000;
  const g = diagnostics(f.c, "0.1.0");
  const dev = g.devices.find((x) => x.id === "mbp")!;
  assert.equal(dev.policy.applied, 1);
  assert.equal(dev.health.stale, true, "15 minutes without a report is stale, not green");
  assert.equal(dev.health.effective_coverage, "degraded");
  assert.ok(dev.health.evidence_age_s! >= 900);
  assert.deepEqual(dev.capabilities.downgraded.map((c) => c.key), ["app_enforcement"]);
  assert.ok(dev.spool.gaps.length >= 1, "the missing sequence range is reported");
  assert.equal(g.controller.policy_revision, 1);
  assert.equal(g.compatibility_tests.run.length, 0, "no compatibility test result is invented");
});
