/**
 * W13 fleet reconciliation: desired vs current per device, staged rollouts, and offline local changes.
 *
 *  - Desired revision for a device = the newest snapshot for its platform that has been *released to it*: a revision
 *    with a rollout reaches only devices in its opened stages; devices outside keep the newest earlier released one.
 *  - Current = what the endpoint acknowledged (applied / confirmed receipts). Distributed or received without an
 *    applied receipt is `pending`; pending beyond STALE_AFTER_MS, or a silent device, is `stale`. Nothing is shown as
 *    current without the endpoint's receipt.
 *  - An offline local change (the endpoint reports one made under local owner authority while the controller was
 *    unreachable) *holds* distribution to that device until the owner reconciles. The controller never overwrites it
 *    by recency, and never adopts it into the fleet by recency either: both directions need an owner decision.
 *  - Advancing a rollout stage requires every device in the opened stages to have acknowledged the revision.
 */
import { audit, HttpError, tx } from "./db.ts";
import type { Controller, Principal } from "./controller.ts";

export const RECONCILE_STALE_MS = 10 * 60_000;

export interface RolloutStage { name: string; devices: string[] }

function rollout(c: Controller, revision: number): { stages: RolloutStage[]; opened: number } | null {
  const r = c.db.prepare("SELECT stages, opened FROM rollouts WHERE revision = ?").get(revision) as { stages: string; opened: number } | undefined;
  return r ? { stages: JSON.parse(r.stages) as RolloutStage[], opened: r.opened } : null;
}

function releasedTo(c: Controller, revision: number, deviceId: string): boolean {
  const r = rollout(c, revision);
  if (!r) return true;
  return r.stages.slice(0, r.opened).some((s) => s.devices.includes(deviceId));
}

export function holdReason(c: Controller, deviceId: string): string | null {
  const lc = c.db.prepare("SELECT revision, broadening, authorized_by FROM local_changes WHERE device_id = ? AND resolved_at IS NULL ORDER BY reported_at DESC LIMIT 1").get(deviceId) as { revision: number; broadening: number; authorized_by: string | null } | undefined;
  if (lc?.authorized_by === "owner-kept-local") return "you kept this device's local policy; fleet revisions are held for it until you choose to apply the fleet revision";
  return lc ? `local change r${lc.revision}${lc.broadening ? " (broadening)" : ""} on the device waits for the owner; fleet revisions are held for this device` : null;
}

/** The snapshot this device should run, or null (nothing released, or held for an unresolved local change). */
export function desiredSnapshot(c: Controller, deviceId: string, platform: string): { revision: number; signed: string | null } | null {
  if (holdReason(c, deviceId)) return null;
  // the newest revision released to this device; its own platform snapshot or nothing (never an older revision's
  // snapshot because the released one has none for this platform, issue #26)
  const revs = c.db.prepare("SELECT revision FROM policy_revisions ORDER BY revision DESC LIMIT 50").all() as { revision: number }[];
  const r = revs.find((x) => releasedTo(c, x.revision, deviceId));
  if (!r) return null;
  const row = c.db.prepare("SELECT signed FROM snapshots WHERE revision = ? AND platform = ?").get(r.revision, platform) as { signed: string } | undefined;
  return { revision: r.revision, signed: row?.signed ?? null };
}

export function recordLocalChange(c: Controller, deviceId: string, lc: { revision?: unknown; digest?: unknown; broadening?: unknown; authorized_by?: unknown }) {
  const rev = Number(lc.revision);
  const digest = String(lc.digest ?? "");
  if (!Number.isInteger(rev) || rev < 0 || !/^sha256:[0-9a-f]{64}$/.test(digest)) throw new HttpError(400, "local_change needs an integer revision and a sha256: digest");
  c.db.prepare("INSERT OR IGNORE INTO local_changes (device_id, revision, digest, broadening, authorized_by, reported_at) VALUES (?, ?, ?, ?, ?, ?)").run(deviceId, rev, digest, lc.broadening ? 1 : 0, lc.authorized_by ? String(lc.authorized_by).slice(0, 128) : null, c.now().toISOString());
}

/** Owner decision on a held device: keep the fleet revision (the device will receive it) or keep the local change
 * (the device stays on it; fleet distribution stays paused for it until a new fleet revision is approved for it). */
export function resolveLocalChange(c: Controller, actor: Principal, deviceId: string, resolution: unknown) {
  c.require(actor, "owner");
  if (resolution !== "apply_fleet" && resolution !== "keep_local") throw new HttpError(400, 'resolution must be "apply_fleet" or "keep_local"');
  const open = c.db.prepare("SELECT revision FROM local_changes WHERE device_id = ? AND resolved_at IS NULL").all(deviceId) as { revision: number }[];
  if (!open.length) throw new HttpError(404, "no unresolved local change on that device");
  tx(c.db, () => {
    c.db.prepare("UPDATE local_changes SET resolved_at = ?, resolution = ?, resolved_by = ? WHERE device_id = ? AND resolved_at IS NULL").run(c.now().toISOString(), resolution, actor.id, deviceId);
    if (resolution === "keep_local") {
      // Keep the device where it is: release no newer fleet revision to it until the owner rolls out to it explicitly.
      const latest = c.db.prepare("SELECT MAX(revision) AS r FROM policy_revisions").get() as { r: number | null };
      if (latest.r) c.db.prepare("INSERT INTO local_changes (device_id, revision, digest, broadening, authorized_by, reported_at) VALUES (?, ?, 'owner-pin', 0, 'owner-kept-local', ?)").run(deviceId, latest.r, c.now().toISOString());
    }
    audit(c.db, c.now(), actor.id, "device.local_change.resolve", deviceId, { resolution, revisions: open.map((o) => o.revision) });
  });
  return { device: deviceId, resolution, held: holdReason(c, deviceId) };
}

export function createRollout(c: Controller, actor: Principal, b: { revision?: unknown; stages?: unknown }) {
  c.require(actor, "owner");
  const revision = Number(b.revision);
  const exists = c.db.prepare("SELECT 1 FROM policy_revisions WHERE revision = ?").get(revision);
  if (!exists) throw new HttpError(404, "no such revision");
  const stages = (Array.isArray(b.stages) ? b.stages : []) as RolloutStage[];
  if (!stages.length || stages.some((s) => !s || typeof s.name !== "string" || !Array.isArray(s.devices) || !s.devices.length)) throw new HttpError(400, "stages must be a non-empty list of { name, devices: [ids] }");
  const known = new Set((c.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").all() as { id: string }[]).map((r) => r.id));
  const all = stages.flatMap((s) => s.devices);
  const unknown = all.filter((d) => !known.has(d));
  if (unknown.length) throw new HttpError(400, `unknown or revoked devices: ${unknown.join(", ")}`);
  if (new Set(all).size !== all.length) throw new HttpError(400, "a device may appear in only one stage");
  const delivered = c.db.prepare("SELECT DISTINCT device_id FROM device_revisions WHERE revision = ? AND state IN ('distributed','received','applied','confirmed')").all(revision) as { device_id: string }[];
  const outside = delivered.map((r) => r.device_id).filter((dv) => !stages[0]!.devices.includes(dv));
  if (outside.length) throw new HttpError(409, `revision ${revision} already reached ${outside.join(", ")}; a rollout cannot un-send it (roll back instead)`);
  const now = c.now().toISOString();
  c.db.prepare("INSERT INTO rollouts (revision, stages, opened, created_by, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?)").run(revision, JSON.stringify(stages), actor.id, now, now);
  audit(c.db, c.now(), actor.id, "rollout.create", String(revision), { stages });
  return rolloutStatus(c, revision);
}

/** Open the next stage only when every device in the opened stages acknowledged the revision. */
export function advanceRollout(c: Controller, actor: Principal, revision: number) {
  c.require(actor, "owner");
  const r = rollout(c, revision);
  if (!r) throw new HttpError(404, "no rollout for that revision");
  if (r.opened >= r.stages.length) throw new HttpError(409, "every stage is already open");
  const st = rolloutStatus(c, revision);
  const notYet = st.devices.filter((d) => d.stage < r.opened && d.state !== "current");
  if (notYet.length) throw new HttpError(409, `not advancing: ${notYet.map((d) => `${d.device} is ${d.state}`).join(", ")}`);
  c.db.prepare("UPDATE rollouts SET opened = opened + 1, updated_at = ? WHERE revision = ?").run(c.now().toISOString(), revision);
  audit(c.db, c.now(), actor.id, "rollout.advance", String(revision), { opened: r.opened + 1 });
  return rolloutStatus(c, revision);
}

type DevState = "current" | "pending" | "stale" | "rejected" | "held" | "not_released" | "ahead";

/** Per-device state for one revision, from receipts only. */
function deviceState(c: Controller, deviceId: string, revision: number): { state: DevState; detail: string | null; at: string | null } {
  const hold = holdReason(c, deviceId);
  if (hold) return { state: "held", detail: hold, at: null };
  const rows = c.db.prepare("SELECT revision, state, at, detail FROM device_revisions WHERE device_id = ? AND revision >= ? ORDER BY revision DESC, at DESC").all(deviceId, revision) as { revision: number; state: string; at: string; detail: string | null }[];
  const mine = rows.filter((r) => r.revision === revision);
  if (mine.some((r) => r.state === "rejected")) return { state: "rejected", detail: mine.find((r) => r.state === "rejected")!.detail, at: mine[0]!.at };
  if (rows.some((r) => r.revision > revision && ["applied", "confirmed"].includes(r.state))) return { state: "ahead", detail: "a newer revision is applied", at: null };
  const ack = mine.find((r) => r.state === "applied" || r.state === "confirmed" || r.state === "verified");
  if (ack) return { state: "current", detail: null, at: ack.at };
  const sent = mine.find((r) => r.state === "distributed" || r.state === "received" || r.state === "trial");
  const dev = c.db.prepare("SELECT last_seen_at, enrolled_at FROM devices WHERE id = ?").get(deviceId) as { last_seen_at: string | null; enrolled_at: string };
  const silentFor = c.now().getTime() - Date.parse(dev.last_seen_at ?? dev.enrolled_at);
  if (!sent) return { state: silentFor > RECONCILE_STALE_MS ? "stale" : "pending", detail: silentFor > RECONCILE_STALE_MS ? "the device has not synced since this revision was approved" : "approved; not yet delivered", at: null };
  const age = c.now().getTime() - Date.parse(sent.at);
  return age > RECONCILE_STALE_MS ? { state: "stale", detail: `delivered ${Math.round(age / 60_000)} min ago; no applied receipt`, at: sent.at } : { state: "pending", detail: `${sent.state}; waiting for the applied receipt`, at: sent.at };
}

export function rolloutStatus(c: Controller, revision: number) {
  const r = rollout(c, revision);
  const devices = (c.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string }[]).map((d) => {
    const stage = r ? r.stages.findIndex((s) => s.devices.includes(d.id)) : 0;
    const released = releasedTo(c, revision, d.id);
    const st = released ? deviceState(c, d.id, revision) : { state: "not_released" as DevState, detail: stage < 0 ? "not in any stage" : `stage ${stage + 1} not opened`, at: null };
    return { device: d.id, stage: stage < 0 ? Infinity : stage, ...st };
  });
  return { revision, stages: r?.stages ?? null, opened: r?.opened ?? null, devices };
}

/** Desired vs current for every device. */
export function reconciliation(c: Controller) {
  const devices = c.db.prepare("SELECT id, platform, last_revision, last_seen_at FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string; platform: string; last_revision: number | null; last_seen_at: string | null }[];
  return devices.map((d) => {
    const platform = d.platform === "macos" ? "macos" : "linux";
    const desired = desiredSnapshot(c, d.id, platform);
    const st = desired ? deviceState(c, d.id, desired.revision) : { state: (holdReason(c, d.id) ? "held" : "current") as DevState, detail: holdReason(c, d.id), at: null };
    return { device: d.id, desired: desired?.revision ?? null, current: d.last_revision, last_seen_at: d.last_seen_at, ...st };
  });
}
