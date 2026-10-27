/**
 * W03 acceptance (controller/signer side): exact grant scope survives every hop, idempotent retries keep the
 * original deadline, publication is serialized and journaled, and phone approvals use a narrowly delegated issuer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { delegationString, generateKeyPair, grantApprovalString, ownerAuthorizationString, requestString, sha256hex, signB64, token, type KeyPair } from "../src/crypto.ts";
import { planDigest, Signer, type Delegation, type GrantPlan, type SignResult } from "../src/signer.ts";
import type { SignerLike } from "../src/controller.ts";
import { bootstrap, fixture, type Fixture } from "./helpers.ts";

function enrollDevice(f: Fixture, id: string, platform = "linux") {
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  const kp = generateKeyPair();
  f.c.enroll({ code, device_id: id, platform, public_hex: kp.publicHex, capabilities: { capabilities: { session_enforcement: { support: "supported" } } } });
  return kp;
}
function dev(f: Fixture, kp: KeyPair, id: string) {
  const ts = new Date(f.clock.t).toISOString();
  const nonce = token(18);
  return f.c.authenticateDevice("POST", "/v1/device/sync", { "x-moat-device": id, "x-moat-ts": ts, "x-moat-nonce": nonce, "x-moat-sig": signB64(kp.privateKey, requestString("POST", "/v1/device/sync", ts, nonce, "{}")) }, "{}");
}
let seq = 0;
function blocked(f: Fixture, kp: KeyPair, deviceId: string, session: string, ip = "203.0.113.50", port = 443) {
  const at = new Date(f.clock.t).toISOString();
  f.c.sync(dev(f, kp, deviceId) as never, {
    events: [
      { seq: ++seq, at, event: { type: "session_started", session_id: session, profile: "coding-session", cgroup: "x", uid: 1000, root_pid: 1, root_start: 1, boundary: "linux_cgroup" } },
      { seq: ++seq, at, event: { type: "flow", attempt: { id: `f${seq}`, device_id: deviceId, app: { family: "curl", executable: "/usr/bin/curl" }, remote_ip: ip, remote_port: port, transport: "tcp", at, session: { id: session, profile: "coding-session", boundary: "linux_cgroup", verified: true }, process: { device_id: deviceId, boot_id: "boot-1", pid: 4300, start_generation: 7 } }, decision: { verdict: "deny", profile: "coding-session", policy_revision: 1 } } },
    ],
  });
  return f.c.incidents().find((i) => i.device_id === deviceId && i.destination === ip && i.session_id === session)!;
}
function delegate(owner: KeyPair, issuer: KeyPair, scope: Partial<Delegation["scope"]> = {}, notAfter = "2099-01-01T00:00:00.000Z"): Delegation {
  const body = { schema: "moat.delegation.v1" as const, issuer_key_id: issuer.keyId, issuer_public_hex: issuer.publicHex, label: "phone", scope: { kinds: ["allow_once"], devices: ["omarchy"], max_ttl_seconds: 3600, ...scope }, not_after: notAfter, owner_key_id: owner.keyId };
  return { ...body, signature: signB64(owner.privateKey, delegationString(body)) };
}
const approve = (issuer: KeyPair, digest: string) => signB64(issuer.privateKey, grantApprovalString(digest));

async function explain(f: Fixture, policy: string, flow: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), "moat-x-"));
  writeFileSync(join(dir, "p.json"), policy);
  writeFileSync(join(dir, "f.json"), JSON.stringify(flow));
  const r = await f.moatctl.run(["--json", "explain", "--flow", join(dir, "f.json"), join(dir, "p.json")]);
  const j = JSON.parse(r.stdout) as { verdict: string; winner?: { kind: string; id: string } };
  return { verdict: j.verdict, winner: j.winner ? `${j.winner.kind}:${j.winner.id}` : undefined };
}
const flowFrom = (device: string, at: string, extra: Record<string, unknown> = {}) => ({ id: "x", device_id: device, user: "robert", app: { family: "curl", executable: "/usr/bin/curl" }, ancestry_complete: true, remote_ip: "203.0.113.50", remote_port: 443, transport: "tcp", at, ...extra });

test("W03: two devices with the same executable never share a single-device exception", async () => {
  const f = fixture();
  enrollDevice(f, "omarchy");
  enrollDevice(f, "arch-2");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const g = await f.c.createGrant(owner, { device_id: "omarchy", app_executable: "/usr/bin/curl", destination: "203.0.113.50", port: 443, operation_id: "op-two-devices-1", ttl_seconds: 600 });
  const eff = f.c.currentRevision()!.effective_source;
  const at = new Date(f.clock.t + 60_000).toISOString();
  const onA = await explain(f, eff, flowFrom("omarchy", at));
  const onB = await explain(f, eff, flowFrom("arch-2", at));
  assert.equal(onA.verdict, "allow");
  assert.equal(onA.winner, `rule:${g.grant_id}`);
  assert.notEqual(onB.winner, `rule:${g.grant_id}`, "the grant does not apply on the other device");
  // (on arch-2 an ordinary app falls back to the observe profile: permitted by observation, not by the grant)
  const after = await explain(f, eff, flowFrom("omarchy", new Date(f.clock.t + 601_000).toISOString()));
  assert.notEqual(after.winner, `rule:${g.grant_id}`, "and not after its deadline");
});

test("W03: a session grant is bound to the session and device; process-scoped grants stay unavailable", async () => {
  const f = fixture();
  const kp = enrollDevice(f, "omarchy");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const inc = blocked(f, kp, "omarchy", "20261027-s1");
  const g = (await f.c.allowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1 })) as { grant_id: string };
  const eff = f.c.currentRevision()!.effective_source;
  const at = new Date(f.clock.t + 60_000).toISOString();
  const sess = (id: string) => ({ session: { id, profile: "coding-session", boundary: "linux_cgroup", verified: true } });
  assert.equal((await explain(f, eff, flowFrom("omarchy", at, sess("20261027-s1")))).winner, `rule:${g.grant_id}`);
  assert.notEqual((await explain(f, eff, flowFrom("omarchy", at, sess("20261027-s2")))).winner, `rule:${g.grant_id}`, "another session on the same device");
  assert.notEqual((await explain(f, eff, flowFrom("arch-2", at, sess("20261027-s1")))).winner, `rule:${g.grant_id}`, "the same session id on another device");
  const status = f.c.grantStatus(g.grant_id);
  assert.equal(status.device_id, "omarchy");
  const plan = JSON.parse((f.c.db.prepare("SELECT plan FROM grant_plans WHERE grant_id = ?").get(g.grant_id) as { plan: string }).plan) as GrantPlan;
  assert.deepEqual(plan.scope, { kind: "task", device_id: "omarchy", boot_id: "boot-1", task_id: "20261027-s1" });
  await assert.rejects(f.c.createGrant(owner, { device_id: "omarchy", session_id: "20261027-s1", process_instance: "omarchy/boot-1/4300@7", destination: "203.0.113.50", port: 443, operation_id: "op-process-1" }), /process-scoped grants are unavailable/);
});

test("W03: duplicate and lost requests keep the original deadline; a retry never mints a fresh lease", async () => {
  const f = fixture();
  const kp = enrollDevice(f, "omarchy");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const inc = blocked(f, kp, "omarchy", "20261027-s3");
  const req = { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1, ttl_seconds: 900, operation_id: "click-7f3a2b1c" };
  const p1 = f.c.planAllowOnce(owner, req);
  f.clock.t += 60_000;
  const p2 = f.c.planAllowOnce(owner, req);
  assert.equal(p2.plan_id, p1.plan_id, "same operation, same plan");
  assert.equal(p2.plan.admission_until, p1.plan.admission_until);
  const g1 = await f.c.commitGrant(owner, { plan_id: p1.plan_id });
  f.clock.t += 120_000;
  const g2 = await f.c.commitGrant(owner, { plan_id: p1.plan_id });
  assert.equal(g2.grant_id, g1.grant_id);
  assert.equal(g2.expires_at, p1.plan.admission_until, "the replay reports the original expiry");
  assert.equal(f.c.currentRevision()!.revision, 2, "no second revision for a replay");
  const g3 = (await f.c.allowOnce(owner, req)) as { grant_id: string; expires_at: string; idempotent_replay?: boolean };
  assert.equal(g3.grant_id, g1.grant_id);
  assert.equal(g3.expires_at, p1.plan.admission_until);
  // a different click (new operation) on the same incident is a new request against the new policy revision
  await assert.rejects(f.c.allowOnce(owner, { ...req, operation_id: "click-other-001" }), /stale: policy is now revision 2/);
  // another principal cannot replay someone else's operation
  const other = f.c.authenticate(f.c.createToken("chloe", "owner").token)!;
  assert.throws(() => f.c.planAllowOnce(other, { ...req, policy_revision: 2 }), /stale|another principal/);
});

test("W03: concurrent publications are serialized into consecutive revisions without conflict", async () => {
  const f = fixture();
  const kp = enrollDevice(f, "omarchy");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const p = [0, 1, 2].map((i) => f.c.planGrant(owner, { device_id: "omarchy", app_executable: "/usr/bin/curl", destination: `198.51.100.${i + 1}`, port: 443, operation_id: `concurrent-${i}-xyz` }));
  void kp;
  const out = await Promise.all(p.map((x) => f.c.commitGrant(owner, { plan_id: x.plan_id })));
  assert.deepEqual(out.map((o) => o.revision).sort(), [2, 3, 4]);
  assert.equal(f.signer.lastRevision, 4);
  const pubs = f.c.publications() as { status: string }[];
  assert.ok(pubs.every((x) => x.status === "committed"));
  const eff = JSON.parse(f.c.currentRevision()!.effective_source) as { rules: { id: string }[] };
  assert.equal(eff.rules.filter((r) => r.id.startsWith("grant-")).length, 3, "the last revision carries every grant");
});

test("W03: a crash after signing (lost reply) recovers the same revision instead of a conflicting one", async () => {
  const f = fixture();
  const kp = enrollDevice(f, "omarchy");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const real = f.c.signer;
  let drop = true;
  const lossy: SignerLike = {
    keyId: real.keyId,
    publicHex: real.publicHex,
    async sign(r) {
      const res = await real.sign(r);
      if (drop) {
        drop = false;
        throw new Error("socket hang up");
      }
      return res;
    },
    publication: (id) => real.publication!(id),
  };
  f.c.signer = lossy;
  const inc = blocked(f, kp, "omarchy", "20261027-s4");
  const plan = f.c.planAllowOnce(owner, { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1 });
  await assert.rejects(f.c.commitGrant(owner, { plan_id: plan.plan_id }), /socket hang up/);
  assert.equal(f.c.currentRevision()!.revision, 1, "nothing stored as active");
  assert.equal(f.signer.lastRevision, 2, "but the signer did sign revision 2");
  assert.equal((f.c.publications() as { status: string }[])[0]!.status, "uncertain");
  assert.equal(f.c.grants().length, 0, "the grant is not active while its outcome is unknown");
  const rec = await f.c.recoverPublications();
  assert.match(rec[0]!.outcome, /recovered revision 2/);
  assert.equal(f.c.currentRevision()!.revision, 2);
  const g = f.c.grants()[0]!;
  assert.equal(g.expires_at, plan.plan.admission_until, "recovered with the original deadline");
  // the retry of the same plan is an idempotent replay now, not revision 3
  const again = await f.c.commitGrant(owner, { plan_id: plan.plan_id }).catch((e) => e as Error);
  assert.ok(!(again instanceof Error) || /stale/.test(again.message));
  assert.equal(f.c.currentRevision()!.revision, 2);
  // signing the same publication again is answered from the journal, never re-signed differently
  const pub = (f.c.publications() as { id: string }[])[0]!.id;
  const journaled = (await f.signer.publication(pub)) as SignResult;
  assert.equal(journaled.revision, 2);
});

test("W03: phone approvals use a narrowly delegated issuer; controller attestation alone is refused", async () => {
  const f = fixture(undefined, { controllerAttestedGrants: false });
  const kp = enrollDevice(f, "omarchy");
  enrollDevice(f, "mbp-m1", "macos");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const phone = generateKeyPair();
  const inc = blocked(f, kp, "omarchy", "20261027-s5");
  const req = { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1, ttl_seconds: 1800 };
  await assert.rejects(f.c.allowOnce(owner, req), /needs a delegated issuer's signature/, "an owner bearer token is not enough");
  assert.throws(() => f.c.registerIssuer(owner, { delegation: { ...delegate(f.owner, phone), issuer_key_id: "0000000000000000" } }), /does not match/);
  f.c.registerIssuer(owner, { delegation: delegate(f.owner, phone) });
  const plan = f.c.planAllowOnce(owner, { ...req, operation_id: "phone-tap-0001" });
  // a signature over a different plan does not transfer
  await assert.rejects(f.c.commitGrant(owner, { plan_id: plan.plan_id, issuer_key_id: phone.keyId, issuer_signature: approve(phone, "sha256:" + "0".repeat(64)) }), /issuer signature over the plan is invalid/);
  const plan2 = f.c.planAllowOnce(owner, { ...req, operation_id: "phone-tap-0002" });
  const g = await f.c.commitGrant(owner, { plan_id: plan2.plan_id, issuer_key_id: phone.keyId, issuer_signature: approve(phone, plan2.digest) });
  assert.equal(g.authorized_by, "delegated_issuer");
  assert.equal(g.issuer_key_id, phone.keyId);
  assert.equal(f.c.revisions()[0]!.authorized_by, "delegated_issuer");
});

test("W03: the signer enforces the delegation's own limits independently of the controller", async () => {
  const f = fixture(undefined, { controllerAttestedGrants: false });
  const kp = enrollDevice(f, "omarchy");
  await bootstrap(f);
  const owner = f.c.authenticate(f.ownerToken)!;
  const phone = generateKeyPair();
  const inc = blocked(f, kp, "omarchy", "20261027-s6");
  const req = { incident_id: inc.id, incident_revision: inc.revision, policy_revision: 1 };
  const tryWith = async (d: Delegation, ttl = 600, op = token(6)) => {
    f.c.registerIssuer(owner, { delegation: d });
    const p = f.c.planAllowOnce(owner, { ...req, ttl_seconds: ttl, operation_id: `limits-${op}` });
    return f.c.commitGrant(owner, { plan_id: p.plan_id, issuer_key_id: phone.keyId, issuer_signature: approve(phone, p.digest) });
  };
  await assert.rejects(tryWith(delegate(f.owner, phone, { devices: ["mbp-m1"] })), /does not cover device omarchy/);
  await assert.rejects(tryWith(delegate(f.owner, phone, { max_ttl_seconds: 300 })), /exceeds the delegated maximum/);
  await assert.rejects(tryWith(delegate(f.owner, phone, { kinds: ["temporary"] })), /does not cover allow_once/);
  await assert.rejects(tryWith(delegate(generateKeyPair(), phone)), /not signed by a trusted owner key/);
  const forged = { ...delegate(f.owner, phone), scope: { kinds: ["allow_once"], devices: ["omarchy"], max_ttl_seconds: 86400 } };
  await assert.rejects(tryWith(forged, 7200), /delegation signature invalid/, "widening a signed delegation breaks it");
  // the signer compares the rule to the approved plan: a controller that alters scope after approval is refused
  const real = new Signer({ seedHex: f.signerKey.seedHex, ownerPublicKeysHex: [f.owner.publicHex], moatctl: f.moatctl });
  const plan = f.c.planAllowOnce(owner, { ...req, ttl_seconds: 600, operation_id: "tamper-00001" }).plan;
  const d = delegate(f.owner, phone);
  const base = f.c.currentRevision()!.source;
  const g = { id: plan.grant_id, kind: "allow_once", device_id: "omarchy", session_id: "20261027-s6", destination: "203.0.113.50", transport: "tcp", port: 8443, expires_at: plan.admission_until, created_by: "robert", reason: "x|audit:1" };
  const tampered = await f.c.effectiveSource(base, [g]);
  const boot = await real.sign({ subject: "bootstrap", source: base, revision: 1, platforms: ["linux"], ownerAuthorization: { key_id: f.owner.keyId, signature: signB64(f.owner.privateKey, ownerAuthorizationString("bootstrap", sha256hex(base))) }, issuedAt: new Date(f.clock.t) });
  assert.equal(boot.authorizedBy, "owner_key");
  await assert.rejects(real.sign({ subject: plan.grant_id, source: tampered, revision: 2, platforms: ["linux"], grantApprovals: [{ plan, delegation: d, issuer_signature: approve(phone, planDigest(plan)) }], issuedAt: new Date(f.clock.t) }), /transport\/port differs from the approved plan/);
  const honest = await f.c.effectiveSource(base, [{ ...g, port: 443 }]);
  const ok = await real.sign({ subject: plan.grant_id, source: honest, revision: 2, platforms: ["linux"], grantApprovals: [{ plan, delegation: d, issuer_signature: approve(phone, planDigest(plan)) }], issuedAt: new Date(f.clock.t) });
  assert.equal(ok.authorizedBy, "delegated_issuer");
});

test("W03: roles — viewers, agents and launchers cannot plan, commit or delegate", async () => {
  const f = fixture();
  enrollDevice(f, "omarchy");
  await bootstrap(f);
  for (const role of ["viewer", "agent", "launcher"] as const) {
    const p = f.c.authenticate(f.c.createToken(role, role).token)!;
    assert.throws(() => f.c.planGrant(p, { device_id: "omarchy", session_id: "s", destination: "203.0.113.1", port: 443, operation_id: "role-check-1" }), /role owner/);
    await assert.rejects(f.c.commitGrant(p, { plan_id: "x" }), /role owner/);
    assert.throws(() => f.c.registerIssuer(p, { delegation: {} }), /role owner/);
  }
});
