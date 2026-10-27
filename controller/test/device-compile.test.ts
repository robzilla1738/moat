/**
 * Issue #26 / Lane A #27: the controller compiles each platform's snapshot for exactly that platform's enrolled
 * devices (`moatctl compile --device`), so app-scoped and hostname rules scoped to Macs do not refuse the Linux
 * snapshot in a mixed fleet, and a snapshot never reaches a device it was not compiled for.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, requestString, signB64, token } from "../src/crypto.ts";
import { normalizeTargets, SignerError } from "../src/signer.ts";
import { bootstrap, fixture, ROOT, type Fixture } from "./helpers.ts";

const SCOPED = readFileSync(join(ROOT, "conformance/policies/home-device-scoped.toml"), "utf8");

function enroll(f: Fixture, id: string, platform: string) {
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  const kp = generateKeyPair();
  f.c.enroll({ code, device_id: id, platform, public_hex: kp.publicHex });
  return kp;
}

function syncAs(f: Fixture, kp: ReturnType<typeof generateKeyPair>, id: string, body: Record<string, unknown>) {
  const text = JSON.stringify(body);
  const ts = new Date(f.clock.t).toISOString();
  const nonce = token(18);
  const d = f.c.authenticateDevice("POST", "/v1/device/sync", { "x-moat-device": id, "x-moat-ts": ts, "x-moat-nonce": nonce, "x-moat-sig": signB64(kp.privateKey, requestString("POST", "/v1/device/sync", ts, nonce, text)) }, text);
  return f.c.sync(d as never, body as never) as { snapshot: { payload: string } | null; snapshot_pending?: string };
}

const payload = (s: { payload: string }) => JSON.parse(Buffer.from(s.payload, "base64").toString("utf8")) as { devices: string[]; platform: string; revision: number; report: { omitted?: { rule_id: string; reason?: string }[] } };

async function verify(f: Fixture, signed: unknown, adapter: string, device: string) {
  const dir = mkdtempSync(join(tmpdir(), "moat-dc-"));
  writeFileSync(join(dir, "s.json"), JSON.stringify(signed));
  writeFileSync(join(dir, "k.pub"), f.signer.publicHex);
  return f.moatctl.run(["verify", join(dir, "s.json"), "--pub", join(dir, "k.pub"), "--adapter", adapter, "--device", device]);
}

test("mixed fleet: a Mac app block and a laptop hostname block compile; Linux gets its own device-targeted snapshot", async () => {
  const f = fixture();
  const lin = enroll(f, "omarchy", "linux");
  const mac = enroll(f, "mbp-m1", "macos");
  const out = (await bootstrap(f, SCOPED)) as { revision: number; platforms: { platform: string; report: { omitted?: { rule_id: string }[] } }[] };
  assert.equal(out.revision, 1);

  const ls = syncAs(f, lin, "omarchy", { last_applied: null }).snapshot!;
  const lp = payload(ls);
  assert.deepEqual([lp.platform, lp.devices], ["linux", ["omarchy"]]);
  const omitted = (lp.report.omitted ?? []).map((o) => o.rule_id);
  assert.ok(omitted.includes("mac-block-zoom"), `Mac app rule left out of the Linux snapshot with a report: ${omitted}`);
  assert.ok(omitted.includes("laptops-block-tracker"), "laptop hostname rule left out of the Linux snapshot");
  assert.equal((await verify(f, ls, "linux", "omarchy")).code, 0);

  const ms = syncAs(f, mac, "mbp-m1", { last_applied: null }).snapshot!;
  const mp = payload(ms);
  assert.deepEqual([mp.platform, mp.devices], ["macos", ["mbp-m1"]]);
  assert.ok(!(mp.report.omitted ?? []).some((o) => o.rule_id === "mac-block-zoom"), "the Mac keeps its own app rule");
  assert.equal((await verify(f, ms, "macos", "mbp-m1")).code, 0);
  assert.notEqual((await verify(f, ms, "macos", "mbp-air")).code, 0, "another Mac refuses a snapshot compiled for mbp-m1");
});

test("Mac-only fleet: Mac-scoped rules publish; no Linux snapshot is made (never a weaker one); a later Linux device waits for a retarget", async () => {
  const f = fixture();
  const owner = f.c.authenticate(f.ownerToken)!;
  enroll(f, "mbp-m1", "macos");
  const out = (await bootstrap(f, SCOPED)) as { platforms: { platform: string }[]; skipped_platforms: { platform: string; reason: string }[] };
  assert.deepEqual(out.platforms.map((p) => p.platform), ["macos"]);
  assert.equal(out.skipped_platforms[0]?.platform, "linux");
  assert.match(out.skipped_platforms[0]!.reason, /fleet-wide linux compile refuses/);
  const lin = enroll(f, "omarchy", "linux");
  const pending = syncAs(f, lin, "omarchy", { last_applied: null });
  assert.equal(pending.snapshot, null, "no older or weaker Linux snapshot is handed out");
  assert.match(pending.snapshot_pending ?? "", /no linux snapshot/);
  assert.deepEqual(f.c.untargetedDevices().map((u) => u.device_id), ["omarchy"]);
  const r = await f.c.retarget(owner);
  assert.equal(r.revision, 2);
  const got = syncAs(f, lin, "omarchy", { last_applied: null }).snapshot!;
  const p = payload(got);
  assert.deepEqual([p.platform, p.devices, p.revision], ["linux", ["omarchy"], 2]);
  assert.ok((p.report.omitted ?? []).some((o) => o.rule_id === "mac-block-zoom"));
});

test("a proposal that cannot compile for an enrolled device's platform is refused before review", async () => {
  const f = fixture();
  enroll(f, "omarchy", "linux");
  const owner = f.c.authenticate(f.ownerToken)!;
  const bad = SCOPED.replace('selector = { devices = ["mbp-m1"], apps', 'selector = { devices = ["omarchy"], apps');
  assert.notEqual(bad, SCOPED);
  await assert.rejects(f.c.propose(owner, bad, "app rule on a Linux device"), /does not compile for this fleet: linux \(devices omarchy\)/);
});

test("a device enrolled after publication gets nothing until the owner retargets; retarget is non-broadening and names it", async () => {
  const f = fixture();
  const owner = f.c.authenticate(f.ownerToken)!;
  enroll(f, "omarchy", "linux");
  await bootstrap(f);
  const late = enroll(f, "linux-2", "linux");
  const first = syncAs(f, late, "linux-2", { last_applied: null });
  assert.equal(first.snapshot, null, "a snapshot compiled for omarchy is never handed to linux-2");
  assert.match(first.snapshot_pending ?? "", /compiled for omarchy/);
  assert.deepEqual(f.c.untargetedDevices().map((u) => u.device_id), ["linux-2"]);
  assert.equal((f.c.devices().find((d) => d.id === "linux-2") as { awaiting_retarget: boolean }).awaiting_retarget, true);
  const rev = f.c.revisions()[0]!;
  assert.ok((rev.devices as { device_id: string; state: string }[]).some((d) => d.device_id === "linux-2" && d.state === "not_targeted"));

  await assert.rejects(f.c.retarget(f.c.createToken("v", "viewer") && f.c.authenticate(f.c.createToken("v2", "viewer").token)!), /role owner/);
  const r = await f.c.retarget(owner);
  assert.equal(r.retargeted, true);
  assert.equal(r.revision, 2);
  const pub = f.c.revisions()[0]! as { revision: number; authorized_by?: string };
  assert.equal(pub.revision, 2);
  const got = syncAs(f, late, "linux-2", { last_applied: null }).snapshot!;
  assert.deepEqual(payload(got).devices, ["linux-2", "omarchy"]);
  assert.equal((await verify(f, got, "linux", "linux-2")).code, 0);
  assert.deepEqual(f.c.untargetedDevices(), []);
  assert.deepEqual(await f.c.retarget(owner), { retargeted: false, missing: [] }, "nothing to retarget: no new revision");
});

test("signer: target lists are part of the publication digest and must be device ids", () => {
  assert.deepEqual(normalizeTargets({ linux: ["b", "a", "a"], macos: [] }), { linux: ["a", "b"] });
  assert.throws(() => normalizeTargets({ linux: ["Bad Id"] }), SignerError);
});
