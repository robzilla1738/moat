/**
 * The Moat controller: enrollment, device sync, policy proposals and revisions, the temporary-grant overlay, bounded
 * "Allow once for this session" actions, incidents (attention queue), the Harness/Dispatch launch API and DNS-only
 * clients. It coordinates; it never sits in the traffic path, never signs (see signer.ts) and never sends shell
 * commands to endpoints — device actions are a closed set of typed operations.
 */
import { isIP } from "node:net";
import { audit, CONTROL_MIGRATIONS, HttpError, openDb, tx, type DB } from "./db.ts";
import { canonicalJson, generateKeyPair, id, keyIdOf, keyPairFromSeed, publicFromHex, requestString, responseString, sha256hex, signB64, token, verifyB64, type KeyPair } from "./crypto.ts";
import { FlowStore, type FlowRecord } from "./flows.ts";
import { Notifier, type FetchLike, type Urgency } from "./notify.ts";
import type { Moatctl } from "./moatctl.ts";
import { contextDigest, contractTime, grantDigest, policyDigest, type ApprovalContext, type Delegation, type GrantApproval, type GrantV1, type OwnerAuthorization, type SignResult } from "./signer.ts";

export type Role = "owner" | "viewer" | "launcher" | "agent";
export interface Principal { id: string; name: string; role: Role }
export interface Proposal { id: string; message: string; author: string; status: string; base_revision: number | null; rollback_of: number | null; created_at: string; source: string; diff: Record<string, unknown>; simulation: Record<string, unknown> | null; broadening: boolean; authorization_subject: string; authorization_digest: string }

/** The signer interface; in production a client for the separate `moat-signer` service. */
export interface SignerLike {
  keyId: string;
  publicHex: string;
  sign(req: { publicationId?: string; subject: string; source: string; grants?: GrantV1[]; revision: number; rollbackOf?: number | null; platforms: ("linux" | "macos" | "dns")[]; targets?: Partial<Record<"linux" | "macos" | "dns", string[]>>; ownerAuthorization?: OwnerAuthorization | null; ownerSessionAttested?: boolean; grantApprovals?: GrantApproval[]; issuedAt: Date }): Promise<SignResult>;
  /** Lost-reply recovery: the result the signer journaled for a publication id, or null if it never signed it. */
  publication?(id: string): Promise<SignResult | null>;
}

export interface ControllerOptions {
  dataDir: string | ":memory:";
  controllerSeedHex?: string;
  signer: SignerLike;
  moatctl: Moatctl;
  now?: () => Date;
  fetch?: FetchLike;
  publicUrl?: string | null;
}

export const DEVICE_ACTIONS = ["close_session"] as const;
export const ALLOW_ONCE_DEFAULT_SECONDS = 3600;
export const ALLOW_ONCE_MAX_SECONDS = 8 * 3600;
/** A grant plan must be approved within this window; the approval then fixes its deadline (retries never extend it). */
export const PLAN_VALID_MS = 5 * 60_000;
const CLOCK_SKEW_MS = 5 * 60_000;
/** A device that has not synced for this long is stale: its last report no longer supports a coverage claim. */
export const STALE_AFTER_MS = 10 * 60_000;

interface DeviceRow { id: string; name: string; platform: string; public_hex: string; key_id: string; enrolled_at: string; revoked_at: string | null; last_seen_at: string | null; capabilities: string | null; last_revision: number | null; coverage: string | null; status: string | null }
interface IncidentRow { id: string; dedup_key: string; kind: string; device_id: string; session_id: string | null; process_instance: string | null; app: string | null; destination: string; port: number | null; transport: string | null; reason: string; rule: string | null; policy_revision: number | null; urgency: Urgency; state: string; occurrences: number; first_at: string; last_at: string; acknowledged_at: string | null; acknowledged_occurrences: number | null; resolved_at: string | null; facts: string; revision: number }

/** A record from an endpoint's spool (moatd `spool::Record`, or the macOS app's equivalent). */
export interface SpoolRecord { seq: number; device_id?: string; boot_id?: string; at: string; event: { type: string; [k: string]: unknown } }

function platformAdapter(p: string): "linux" | "macos" | "dns" {
  return p === "macos" ? "macos" : p === "dns_resolver" ? "dns" : "linux";
}

export class Controller {
  db: DB;
  flows: FlowStore;
  notifier: Notifier;
  signer: SignerLike;
  moatctl: Moatctl;
  now: () => Date;
  key: KeyPair;
  constructor(o: ControllerOptions) {
    const mem = o.dataDir === ":memory:";
    this.db = openDb(mem ? ":memory:" : `${o.dataDir}/control.db`, CONTROL_MIGRATIONS);
    this.flows = new FlowStore(mem ? ":memory:" : `${o.dataDir}/flows.db`);
    this.now = o.now ?? (() => new Date());
    this.notifier = new Notifier(this.db, this.now, o.fetch ?? (async () => ({ status: 599 })), o.publicUrl ?? null);
    this.signer = o.signer;
    this.moatctl = o.moatctl;
    this.key = o.controllerSeedHex ? keyPairFromSeed(o.controllerSeedHex) : generateKeyPair();
  }
  private iso() {
    return this.now().toISOString();
  }

  // ------------------------------------------------------------------ principals
  createToken(name: string, role: Role): { id: string; token: string } {
    const t = `moat_${role}_${token(24)}`;
    const tid = id("tok");
    this.db.prepare("INSERT INTO tokens (id, name, role, token_hash, created_at) VALUES (?, ?, ?, ?, ?)").run(tid, name, role, sha256hex(t), this.iso());
    audit(this.db, this.now(), "system", "token.create", tid, { name, role });
    return { id: tid, token: t };
  }
  authenticate(bearer: string | undefined): Principal | null {
    if (!bearer) return null;
    const r = this.db.prepare("SELECT id, name, role FROM tokens WHERE token_hash = ? AND revoked_at IS NULL").get(sha256hex(bearer)) as Principal | undefined;
    return r ?? null;
  }
  require(p: Principal | null, ...roles: Role[]): Principal {
    if (!p) throw new HttpError(401, "sign in required");
    if (!roles.includes(p.role)) throw new HttpError(403, `this action needs role ${roles.join(" or ")}`);
    return p;
  }
  addOwnerKey(publicHex: string, label: string) {
    publicFromHex(publicHex);
    const kid = keyIdOf(publicHex);
    this.db.prepare("INSERT OR IGNORE INTO owner_keys (key_id, public_hex, label, created_at) VALUES (?, ?, ?, ?)").run(kid, publicHex, label, this.iso());
    return kid;
  }

  // ------------------------------------------------------------------ enrollment & mutual auth
  createEnrollmentCode(actor: Principal, deviceGroups: string[] = [], ttlMinutes = 15) {
    this.require(actor, "owner");
    const code = token(12);
    this.db.prepare("INSERT INTO enrollment_codes (code_hash, created_by, created_at, expires_at, device_groups) VALUES (?, ?, ?, ?, ?)").run(sha256hex(code), actor.id, this.iso(), new Date(this.now().getTime() + ttlMinutes * 60_000).toISOString(), JSON.stringify(deviceGroups));
    audit(this.db, this.now(), actor.id, "enrollment.code", null, { ttl_minutes: ttlMinutes });
    return { code, expires_in_minutes: ttlMinutes };
  }

  enroll(b: { code?: unknown; device_id?: unknown; name?: unknown; platform?: unknown; public_hex?: unknown; capabilities?: unknown }) {
    const code = typeof b.code === "string" ? b.code : "";
    const deviceId = typeof b.device_id === "string" && /^[a-z0-9][a-z0-9-]{0,62}$/.test(b.device_id) ? b.device_id : null;
    if (!deviceId) throw new HttpError(400, "device_id must be lowercase letters, digits and dashes");
    const platform = ["linux", "macos", "windows"].includes(String(b.platform)) ? String(b.platform) : null;
    if (!platform) throw new HttpError(400, "platform must be linux, macos or windows");
    const pub = typeof b.public_hex === "string" ? b.public_hex : "";
    try {
      publicFromHex(pub);
    } catch {
      throw new HttpError(400, "public_hex must be a 32-byte Ed25519 public key in hex");
    }
    return tx(this.db, () => {
      const row = this.db.prepare("SELECT * FROM enrollment_codes WHERE code_hash = ?").get(sha256hex(code)) as { expires_at: string; used_at: string | null } | undefined;
      if (!row || row.used_at || row.expires_at < this.iso()) throw new HttpError(403, "enrollment code invalid, used or expired");
      if (this.db.prepare("SELECT 1 FROM devices WHERE id = ? AND revoked_at IS NULL").get(deviceId)) throw new HttpError(409, "a device with this id is already enrolled");
      this.db.prepare("UPDATE enrollment_codes SET used_at = ?, device_id = ? WHERE code_hash = ?").run(this.iso(), deviceId, sha256hex(code));
      this.db.prepare("INSERT OR REPLACE INTO devices (id, name, platform, public_hex, key_id, enrolled_at, capabilities, coverage) VALUES (?, ?, ?, ?, ?, ?, ?, 'enrolled')")
        .run(deviceId, typeof b.name === "string" ? b.name.slice(0, 80) : deviceId, platform, pub, keyIdOf(pub), this.iso(), b.capabilities ? JSON.stringify(b.capabilities) : null);
      audit(this.db, this.now(), `device:${deviceId}`, "device.enroll", deviceId, { platform, key_id: keyIdOf(pub) });
      return { device_id: deviceId, controller_public_hex: this.key.publicHex, controller_key_id: this.key.keyId, signer_public_hex: this.signer.publicHex, signer_key_id: this.signer.keyId };
    });
  }

  revokeDevice(actor: Principal, deviceId: string) {
    this.require(actor, "owner");
    const r = this.db.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(this.iso(), deviceId);
    if (!r.changes) throw new HttpError(404, "no such active device");
    audit(this.db, this.now(), actor.id, "device.revoke", deviceId, null);
    return { revoked: deviceId };
  }

  /** Verify a device-signed request. Headers: x-moat-device, x-moat-ts, x-moat-nonce, x-moat-sig. */
  authenticateDevice(method: string, path: string, h: Record<string, string | undefined>, body: string): DeviceRow {
    const deviceId = h["x-moat-device"], ts = h["x-moat-ts"], nonce = h["x-moat-nonce"], sig = h["x-moat-sig"];
    if (!deviceId || !ts || !nonce || !sig) throw new HttpError(401, "device signature required");
    const d = this.db.prepare("SELECT * FROM devices WHERE id = ?").get(deviceId) as unknown as DeviceRow | undefined;
    if (!d || d.revoked_at) throw new HttpError(401, "unknown or revoked device");
    if (Math.abs(Date.parse(ts) - this.now().getTime()) > CLOCK_SKEW_MS) throw new HttpError(401, "request timestamp outside the allowed clock skew");
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) throw new HttpError(401, "bad nonce");
    if (!verifyB64(publicFromHex(d.public_hex), requestString(method, path, ts, nonce, body), sig)) throw new HttpError(401, "bad device signature");
    const fresh = this.db.prepare("INSERT OR IGNORE INTO nonces (key_id, nonce, seen_at) VALUES (?, ?, ?)").run(d.key_id, nonce, this.iso());
    if (!fresh.changes) throw new HttpError(401, "replayed request");
    this.db.prepare("DELETE FROM nonces WHERE seen_at < ?").run(new Date(this.now().getTime() - 2 * CLOCK_SKEW_MS).toISOString());
    return d;
  }

  signResponse(status: number, nonce: string, body: string): Record<string, string> {
    const ts = this.iso();
    return { "x-moat-controller": this.key.keyId, "x-moat-ts": ts, "x-moat-nonce": nonce, "x-moat-sig": signB64(this.key.privateKey, responseString(status, ts, nonce, body)) };
  }

  devices() {
    const untargeted = new Set(this.untargetedDevices().map((u) => u.device_id));
    return (this.db.prepare("SELECT * FROM devices WHERE revoked_at IS NULL ORDER BY name").all() as unknown as DeviceRow[]).map((d) => ({
      id: d.id,
      name: d.name,
      platform: d.platform,
      enrolled_at: d.enrolled_at,
      last_seen_at: d.last_seen_at,
      last_revision: d.last_revision,
      coverage: d.coverage,
      ...this.staleness(d),
      status: d.status ? JSON.parse(d.status) : null,
      capabilities: d.capabilities ? JSON.parse(d.capabilities) : null,
      revision_states: this.db.prepare("SELECT revision, state, at, detail FROM device_revisions WHERE device_id = ? ORDER BY revision DESC, at DESC LIMIT 12").all(d.id),
      telemetry_gaps: this.flows.gaps(d.id),
      // the current revision's snapshot for this platform was compiled for devices enrolled before this one
      awaiting_retarget: untargeted.has(d.id),
    }));
  }

  // ------------------------------------------------------------------ device sync
  /** One sync round: receipts and events in; newer signed snapshot and typed actions out. */
  sync(d: DeviceRow, b: { last_applied?: number | null; capabilities?: unknown; status?: unknown; receipts?: { revision: number; state: string; detail?: string }[]; events?: SpoolRecord[] }) {
    const at = this.iso();
    this.db.prepare("UPDATE devices SET last_seen_at = ?, capabilities = COALESCE(?, capabilities), status = COALESCE(?, status), last_revision = COALESCE(?, last_revision) WHERE id = ?")
      .run(at, b.capabilities ? JSON.stringify(b.capabilities) : null, b.status ? JSON.stringify(b.status) : null, b.last_applied ?? null, d.id);
    for (const r of b.receipts ?? []) {
      if (["received", "applied", "rejected"].includes(r.state) && Number.isInteger(r.revision)) this.recordRevisionState(d.id, r.revision, r.state, r.detail ?? null);
    }
    const ingest = this.ingestEvents(d, b.events ?? []);
    // only the current revision's snapshot for this platform; never an older revision's when the current one has none
    const cur = this.currentRevision();
    const latest = cur ? (this.db.prepare("SELECT revision, signed FROM snapshots WHERE revision = ? AND platform = ?").get(cur.revision, platformAdapter(d.platform)) as { revision: number; signed: string } | undefined) : undefined;
    let snapshot: unknown = null;
    let snapshotPending: string | null = null;
    if (cur && !latest && (b.last_applied ?? 0) < cur.revision) {
      snapshotPending = `revision ${cur.revision} has no ${platformAdapter(d.platform)} snapshot (no ${platformAdapter(d.platform)} device was enrolled when it was compiled); this device gets one after the owner retargets (POST /v1/policy/retarget)`;
      this.recordRevisionState(d.id, cur.revision, "not_targeted", snapshotPending);
    }
    if (latest && (b.last_applied ?? 0) < latest.revision) {
      const targets = this.snapshotTargets(latest.signed);
      if (targets.length && !targets.includes(d.id)) {
        // compiled for a device list made before this device enrolled: it would (correctly) refuse it
        snapshotPending = `revision ${latest.revision} was compiled for ${targets.join(", ")}; this device gets a snapshot after the owner retargets (POST /v1/policy/retarget) or the next publication`;
        this.recordRevisionState(d.id, latest.revision, "not_targeted", snapshotPending);
      } else {
        snapshot = JSON.parse(latest.signed);
        this.recordRevisionState(d.id, latest.revision, "distributed", null);
      }
    }
    const actions = this.db.prepare("SELECT id, kind, args FROM device_actions WHERE device_id = ? AND done_at IS NULL ORDER BY created_at").all(d.id) as { id: string; kind: string; args: string }[];
    for (const a of actions) this.db.prepare("UPDATE device_actions SET delivered_at = COALESCE(delivered_at, ?) WHERE id = ?").run(at, a.id);
    return { snapshot, ...(snapshotPending ? { snapshot_pending: snapshotPending } : {}), actions: actions.map((a) => ({ id: a.id, kind: a.kind, args: JSON.parse(a.args) })), acked_seq: ingest.maxSeq, gaps: ingest.gaps };
  }

  recordRevisionState(deviceId: string, revision: number, state: string, detail: string | null) {
    this.db.prepare("INSERT OR IGNORE INTO device_revisions (device_id, revision, state, at, detail) VALUES (?, ?, ?, ?, ?)").run(deviceId, revision, state, this.iso(), detail);
  }

  /** Spool records from an endpoint. Origin is the endpoint (enforcer + launcher); it may report decisions,
   * counters, receipts, sessions and coverage. It may not report another device's events. */
  ingestEvents(d: DeviceRow, events: SpoolRecord[]) {
    const flowRecs: FlowRecord[] = [];
    let maxSeq = 0;
    for (const r of events.slice(0, 5000)) {
      if (!Number.isInteger(r.seq) || r.seq < 1) continue;
      if (r.device_id && r.device_id !== d.id) throw new HttpError(403, "a device may only report its own events");
      maxSeq = Math.max(maxSeq, r.seq);
      const e = r.event;
      switch (e.type) {
        case "policy_applied":
          this.recordRevisionState(d.id, Number(e.revision), "applied", null);
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt", policy_revision: Number(e.revision) });
          break;
        case "policy_rejected":
          if (e.kept_revision !== undefined) this.raise({ kind: "policy_rejected", device: d.id, destination: "-", reason: String(e.reason ?? "rejected"), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt" });
          break;
        case "policy_trial_started":
          this.recordRevisionState(d.id, Number(e.revision), "trial", `reverts to ${e.fallback_revision} at ${e.deadline} unless confirmed on the device`);
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt", policy_revision: Number(e.revision) });
          break;
        case "policy_trial_confirmed":
          this.recordRevisionState(d.id, Number(e.revision), "confirmed", String(e.how ?? "confirmed locally"));
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt", policy_revision: Number(e.revision) });
          break;
        case "policy_rolled_back":
          this.recordRevisionState(d.id, Number(e.from_revision), "rolled_back", `to revision ${e.to_revision}: ${e.reason}`);
          this.raise({ kind: "policy_rolled_back", device: d.id, destination: "-", revision: Number(e.from_revision), reason: `revision ${e.from_revision} was rolled back to ${e.to_revision} on the device (${e.reason})`, urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt", policy_revision: Number(e.to_revision) });
          break;
        case "policy_rollback_failed":
          this.raise({ kind: "policy_rejected", device: d.id, destination: "-", revision: Number(e.revision), reason: String(e.reason ?? "rollback failed"), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "receipt" });
          break;
        case "rule_counter":
          flowRecs.push({ seq: r.seq, at: r.at, kind: "rule_counter", rule: String(e.rule), packets: Number(e.packets ?? 0), bytes_out: Number(e.bytes ?? 0), counter_scope: String(e.scope ?? "rule"), measurement_source: "nftables rule counter", verdict: String(e.rule).startsWith("default:") || String(e.rule).startsWith("session:") ? "deny" : null });
          if (String(e.rule).startsWith("default:") || String(e.rule).startsWith("session:unknown")) {
            this.raise({ kind: "blocked_connection", device: d.id, destination: "rule-scoped", rule: String(e.rule), reason: `${e.packets} packet(s) rejected by ${e.rule} (rule-scoped counter; destination not recorded on this platform)`, urgency: "medium", ref: `seq:${r.seq}`, at: r.at });
          }
          break;
        case "flow": {
          const a = (e.attempt ?? {}) as { app?: { family?: string; executable?: string; team_id?: string; signing_id?: string }; remote_ip?: string; remote_port?: number; transport?: string; hostname?: { name?: string }; session?: { id?: string; verified?: boolean }; process?: { pid?: number; start_generation?: number; boot_id?: string } };
          const dec = (e.decision ?? {}) as { verdict?: "allow" | "deny"; permitted_by_observation?: boolean; rule?: string; profile?: string; policy_revision?: number };
          const dest = a.hostname?.name ?? a.remote_ip ?? "unknown";
          const pi = a.process ? `${d.id}/${a.process.boot_id ?? ""}/${a.process.pid}@${a.process.start_generation}` : null;
          flowRecs.push({ attempt: e.attempt ? JSON.stringify(e.attempt) : null, seq: r.seq, at: r.at, kind: "flow", app: a.app?.family ?? a.app?.executable ?? null, session_id: a.session?.verified ? a.session.id ?? null : null, process_instance: pi, destination: dest, port: a.remote_port ?? null, transport: a.transport ?? null, verdict: dec.verdict ?? null, observed: !!dec.permitted_by_observation, rule: dec.rule ?? (dec.profile ? `default:${dec.profile}` : null), policy_revision: dec.policy_revision ?? null, measurement_source: String(e.measurement_source ?? "endpoint flow decision"), exe: a.app?.executable ?? null, signer: a.app?.team_id || a.app?.signing_id ? [a.app?.team_id, a.app?.signing_id].filter(Boolean).join("/") : null });
          if (dec.verdict === "deny") {
            this.raise({ kind: "blocked_connection", device: d.id, session: a.session?.verified ? a.session.id : undefined, process: pi ?? undefined, app: a.app?.family ?? a.app?.executable, destination: dest, port: a.remote_port, transport: a.transport, rule: dec.rule ?? `default:${dec.profile ?? "?"}`, revision: dec.policy_revision, reason: dec.rule ? `blocked by ${dec.rule}` : `blocked by the ${dec.profile ?? "profile"} default`, urgency: a.session?.verified ? "high" : "medium", ref: `seq:${r.seq}`, at: r.at, facts: { chain: e.chain ?? null, transfer: e.transfer ?? null } });
          }
          break;
        }
        case "session_started":
          this.db.prepare("INSERT OR REPLACE INTO sessions (id, device_id, profile, uid, root_pid, root_start, cgroup, boundary, verified, state, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'running', ?)")
            .run(String(e.session_id), d.id, String(e.profile), Number(e.uid ?? 0), Number(e.root_pid ?? 0), Number(e.root_start ?? 0), String(e.cgroup ?? ""), String(e.boundary ?? "linux_cgroup"), r.at);
          flowRecs.push({ seq: r.seq, at: r.at, kind: "session", session_id: String(e.session_id) });
          break;
        case "session_ended":
          this.db.prepare("UPDATE sessions SET state = 'ended', ended_at = ?, exit_code = ? WHERE device_id = ? AND id = ?").run(r.at, e.exit_code === null || e.exit_code === undefined ? null : Number(e.exit_code), d.id, String(e.session_id));
          this.db.prepare("UPDATE device_actions SET done_at = ? WHERE device_id = ? AND kind = 'close_session' AND json_extract(args, '$.session_id') = ? AND done_at IS NULL").run(r.at, d.id, String(e.session_id));
          flowRecs.push({ seq: r.seq, at: r.at, kind: "session", session_id: String(e.session_id) });
          break;
        case "coverage_changed": {
          const level = String(e.level);
          this.db.prepare("UPDATE devices SET coverage = ? WHERE id = ?").run(level, d.id);
          if (level === "degraded") this.raise({ kind: "coverage_lost", device: d.id, destination: "-", reason: String(e.detail ?? "enforcement not active"), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          // W06 labels: the device kept its last verified policy and needs the owner at the device; never shown as healthy.
          if (level === "recovery-required") this.raise({ kind: "recovery_required", device: d.id, destination: "-", reason: String(e.detail ?? "the activation journal could not reconcile state; the last verified policy stays in force until you recover at the device"), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          if (level === "rollback-pending") this.raise({ kind: "rollback_pending", device: d.id, destination: "-", reason: String(e.detail ?? "a trial rollback could not reinstall the fallback; the trial revision is still in force"), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "coverage", detail: level });
          break;
        }
        case "activation_recovery": {
          // moat.activation.v1 phase names. Only recovery_required needs the owner; other phases are recorded evidence.
          const phase = String(e.phase ?? "unknown");
          if (phase === "recovery_required") {
            this.db.prepare("UPDATE devices SET coverage = 'recovery-required' WHERE id = ?").run(d.id);
            this.raise({ kind: "recovery_required", device: d.id, destination: "-", revision: e.active_revision === undefined || e.active_revision === null ? undefined : Number(e.active_revision), reason: `activation recovery required: ${String(e.detail ?? "")}`.trim(), urgency: "high", ref: `seq:${r.seq}`, at: r.at });
          }
          flowRecs.push({ seq: r.seq, at: r.at, kind: "activation_recovery", policy_revision: e.active_revision === undefined || e.active_revision === null ? null : Number(e.active_revision), detail: `${phase}: ${String(e.detail ?? "")}`.slice(0, 300) });
          break;
        }
        case "session_not_adopted":
          // The daemon restarted and stopped a session it could not re-adopt: the session is over, not running unprotected.
          this.db.prepare("UPDATE sessions SET state = 'ended', ended_at = COALESCE(ended_at, ?), close_requested_at = close_requested_at WHERE device_id = ? AND id = ?").run(r.at, d.id, String(e.session_id));
          this.raise({ kind: "session_not_adopted", device: d.id, session: String(e.session_id), destination: "-", reason: `session ${e.session_id} (${e.profile}) was stopped after a daemon restart: ${e.reason}`, urgency: "medium", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "session_not_adopted", session_id: String(e.session_id), detail: String(e.reason ?? "").slice(0, 300) });
          break;
        case "stream_terminated":
          // Evidence that Moat ended an admitted stream (revocation, isolation, close). Recorded, not an alarm.
          flowRecs.push({ seq: r.seq, at: r.at, kind: "stream_terminated", session_id: String(e.session_id), destination: String(e.hostname ?? e.destination ?? ""), rule: String(e.admitted_by ?? ""), measurement_source: "session egress proxy", detail: String(e.reason ?? "").slice(0, 300) });
          break;
        case "proxy_limit":
          // A bound was reached and the connection was refused (never a bypass). The owner should know the task hit it.
          this.raise({ kind: "proxy_limit", device: d.id, session: String(e.session_id), destination: "-", rule: `limit:${e.resource}`, reason: `the session proxy refused a connection: ${e.resource} limit ${e.limit} reached (refused, not bypassed)`, urgency: "medium", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "proxy_limit", session_id: String(e.session_id), detail: `${e.resource}=${e.limit}` });
          break;
        case "gap":
          this.raise({ kind: "telemetry_gap", device: d.id, destination: "-", reason: `events ${e.from}–${e.to} lost on the device (${e.reason})`, urgency: "medium", ref: `seq:${r.seq}`, at: r.at });
          flowRecs.push({ seq: r.seq, at: r.at, kind: "gap" });
          break;
        default:
          flowRecs.push({ seq: r.seq, at: r.at, kind: e.type.slice(0, 40) });
      }
    }
    const res = this.flows.insertBatch(d.id, flowRecs);
    for (const [from, to] of res.gaps) this.raise({ kind: "telemetry_gap", device: d.id, destination: "-", reason: `controller never received events ${from}–${to}`, urgency: "medium", ref: `gap:${from}-${to}`, at: this.iso() });
    return { maxSeq, gaps: res.gaps };
  }

  // ------------------------------------------------------------------ attention queue
  /**
   * One incident per (device, session or app, destination, port, rule reason). Repeats add occurrences; the same
   * source record seen twice is ignored; acknowledging never resolves; a new occurrence after acknowledgement
   * reopens. Provenance: Digital Kingdom attention queue semantics (apps/server/src/attention.ts @ e0452c8).
   */
  raise(s: { kind: string; device: string; session?: string; process?: string; app?: string; destination: string; port?: number; transport?: string; rule?: string; revision?: number; reason: string; urgency: Urgency; ref: string; at: string; facts?: Record<string, unknown> }) {
    const subject = s.session ? `session:${s.session}` : s.app ? `app:${s.app}` : "device";
    const key = `${s.kind}|${s.device}|${subject}|${s.destination}|${s.port ?? ""}|${s.rule ?? s.reason.slice(0, 40)}`;
    const existing = this.db.prepare("SELECT * FROM incidents WHERE dedup_key = ?").get(key) as unknown as IncidentRow | undefined;
    if (existing) {
      if (this.db.prepare("SELECT 1 FROM incident_log WHERE incident_id = ? AND source_ref = ?").get(existing.id, s.ref)) return existing.id;
      const reopen = existing.state !== "open";
      this.db.prepare("UPDATE incidents SET occurrences = occurrences + 1, last_at = ?, state = 'open', resolved_at = CASE WHEN ? THEN NULL ELSE resolved_at END, process_instance = COALESCE(?, process_instance), policy_revision = COALESCE(?, policy_revision), revision = revision + 1 WHERE id = ?")
        .run(s.at, reopen ? 1 : 0, s.process ?? null, s.revision ?? null, existing.id);
      this.db.prepare("INSERT INTO incident_log (incident_id, type, source_ref, at) VALUES (?, ?, ?, ?)").run(existing.id, reopen ? "reopened" : "occurrence", s.ref, this.iso());
      if (reopen) this.notifier.enqueue(existing.id, `${key}#${existing.revision + 1}`, s.urgency, s.kind);
      return existing.id;
    }
    const iid = id("inc");
    this.db.prepare("INSERT INTO incidents (id, dedup_key, kind, device_id, session_id, process_instance, app, destination, port, transport, reason, rule, policy_revision, urgency, state, occurrences, first_at, last_at, facts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, ?)")
      .run(iid, key, s.kind, s.device, s.session ?? null, s.process ?? null, s.app ?? null, s.destination, s.port ?? null, s.transport ?? null, s.reason, s.rule ?? null, s.revision ?? null, s.urgency, s.at, s.at, JSON.stringify(s.facts ?? {}));
    this.db.prepare("INSERT INTO incident_log (incident_id, type, source_ref, at) VALUES (?, 'raised', ?, ?)").run(iid, s.ref, this.iso());
    this.notifier.enqueue(iid, key, s.urgency, s.kind);
    return iid;
  }

  incidents(state?: string) {
    const rows = (state ? this.db.prepare("SELECT * FROM incidents WHERE state = ? ORDER BY last_at DESC LIMIT 200").all(state) : this.db.prepare("SELECT * FROM incidents ORDER BY last_at DESC LIMIT 200").all()) as unknown as IncidentRow[];
    return rows.map((i) => ({ ...i, facts: JSON.parse(i.facts), new_since_ack: i.acknowledged_occurrences !== null ? i.occurrences - i.acknowledged_occurrences : null }));
  }
  incident(iid: string) {
    const i = this.db.prepare("SELECT * FROM incidents WHERE id = ?").get(iid) as unknown as IncidentRow | undefined;
    if (!i) throw new HttpError(404, "no such incident");
    return { ...i, facts: JSON.parse(i.facts), log: this.db.prepare("SELECT seq, type, source_ref, at, actor FROM incident_log WHERE incident_id = ? ORDER BY seq DESC LIMIT 50").all(iid) };
  }
  /** State changes carry the incident revision the caller saw: a changed incident is never acted on blindly. */
  private precondition(iid: string, expected: unknown): IncidentRow {
    const i = this.db.prepare("SELECT * FROM incidents WHERE id = ?").get(iid) as unknown as IncidentRow | undefined;
    if (!i) throw new HttpError(404, "no such incident");
    if (expected === undefined || expected === null || !Number.isInteger(Number(expected))) throw new HttpError(428, "expected_revision is required: send the incident revision you reviewed");
    if (Number(expected) !== i.revision) throw new HttpError(409, `stale: the incident is now at revision ${i.revision}; review it again`);
    return i;
  }
  acknowledge(actor: Principal, iid: string, expectedRevision?: unknown) {
    this.require(actor, "owner");
    this.precondition(iid, expectedRevision);
    const r = this.db.prepare("UPDATE incidents SET state = 'acknowledged', acknowledged_at = ?, acknowledged_occurrences = occurrences WHERE id = ? AND state = 'open'").run(this.iso(), iid);
    if (r.changes) this.db.prepare("INSERT INTO incident_log (incident_id, type, at, actor) VALUES (?, 'acknowledged', ?, ?)").run(iid, this.iso(), actor.id);
    return this.incident(iid);
  }
  resolve(actor: Principal, iid: string, expectedRevision?: unknown) {
    this.require(actor, "owner");
    const i = this.precondition(iid, expectedRevision);
    if (i.state === "resolved") return this.incident(iid);
    this.db.prepare("UPDATE incidents SET state = 'resolved', resolved_at = ? WHERE id = ?").run(this.iso(), iid);
    this.db.prepare("INSERT INTO incident_log (incident_id, type, at, actor) VALUES (?, 'resolved', ?, ?)").run(iid, this.iso(), actor.id);
    return this.incident(iid);
  }

  // ------------------------------------------------------------------ policy
  currentRevision(): { revision: number; source: string; effective_source: string } | null {
    return (this.db.prepare("SELECT revision, source, effective_source FROM policy_revisions ORDER BY revision DESC LIMIT 1").get() as { revision: number; source: string; effective_source: string } | undefined) ?? null;
  }

  async propose(actor: Principal, source: string, message: string, rollbackOf: number | null = null) {
    this.require(actor, "owner", "agent");
    if (source.length > 512 * 1024) throw new HttpError(413, "policy too large");
    const v = await this.moatctl.validate(source);
    if (!v.ok) {
      if (!v.schemaOk) throw new HttpError(422, `policy invalid: ${v.errors.join("; ")}`);
      // Fleet-wide compilation failed for some adapter. What publishes is one snapshot per platform compiled for that
      // platform's enrolled devices (issue #26): refuse only if one of those targeted compiles fails.
      const plan = await this.compilePlan(source, []);
      if (plan.failed.length || plan.platforms.length === 0) throw new HttpError(422, `policy does not compile for this fleet: ${[...plan.failed, ...plan.skipped.map((x) => `${x.platform}: ${x.reason}`)].join("; ")}`);
    }
    const cur = this.currentRevision();
    const diff = cur ? await this.moatctl.diff(cur.source, source) : { broadening: true, diff: { broadening: ["first policy"] } };
    let simulation: Record<string, unknown> | null = null;
    if (cur) {
      const obs = this.flows.observationsJsonl();
      const unack = (this.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL AND COALESCE(last_revision, 0) < ?").all(cur.revision) as { id: string }[]).map((r) => r.id);
      simulation = await this.moatctl.simulate(cur.source, source, obs, unack).catch((e) => ({ error: String(e) }));
      simulation.note = "Rule-scoped counters cannot be replayed; replay covers endpoints that report per-flow decisions.";
    }
    const pid = id("prop");
    this.db.prepare("INSERT INTO policy_proposals (id, source, source_digest, message, author, base_revision, diff, broadening, simulation, rollback_of, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)")
      .run(pid, source, sha256hex(source), message.slice(0, 500), actor.id, cur?.revision ?? null, JSON.stringify(diff.diff), diff.broadening ? 1 : 0, simulation ? JSON.stringify(simulation) : null, rollbackOf, this.iso());
    audit(this.db, this.now(), actor.id, "policy.propose", pid, { broadening: diff.broadening, rollback_of: rollbackOf });
    return this.proposal(pid);
  }

  proposal(pid: string): Proposal {
    const p = this.db.prepare("SELECT * FROM policy_proposals WHERE id = ?").get(pid) as Record<string, unknown> | undefined;
    if (!p) throw new HttpError(404, "no such proposal");
    return {
      id: String(p.id),
      message: String(p.message),
      author: String(p.author),
      status: String(p.status),
      base_revision: p.base_revision === null ? null : Number(p.base_revision),
      rollback_of: p.rollback_of === null ? null : Number(p.rollback_of),
      created_at: String(p.created_at),
      source: String(p.source),
      diff: JSON.parse(String(p.diff)) as Record<string, unknown>,
      simulation: p.simulation ? (JSON.parse(String(p.simulation)) as Record<string, unknown>) : null,
      broadening: p.broadening === 1,
      authorization_subject: pid,
      authorization_digest: String(p.source_digest),
    };
  }

  private activeGrants() {
    return this.db.prepare("SELECT * FROM grants WHERE revoked_at IS NULL AND expires_at > ? AND committed = 1 ORDER BY created_at").all(this.iso()) as Record<string, unknown>[];
  }

  private platformsNeeded(): ("linux" | "macos" | "dns")[] {
    const set = new Set<"linux" | "macos" | "dns">(["linux", "macos"]);
    for (const r of this.db.prepare("SELECT DISTINCT platform FROM devices WHERE revoked_at IS NULL").all() as { platform: string }[]) set.add(platformAdapter(r.platform));
    set.delete("dns");
    return [...set];
  }

  /** Enrolled, unrevoked devices per compile platform: each platform's snapshot is compiled for exactly these (issue #26). */
  platformTargets(): Partial<Record<"linux" | "macos" | "dns", string[]>> {
    const out: Partial<Record<"linux" | "macos" | "dns", string[]>> = {};
    for (const r of this.db.prepare("SELECT id, platform FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string; platform: string }[]) {
      const p = platformAdapter(r.platform);
      (out[p] ??= []).push(r.id);
    }
    return out;
  }

  /**
   * Which platform snapshots a publication produces. A platform with enrolled devices is compiled for exactly those
   * devices and must compile (`failed` otherwise). A platform with no enrolled devices is compiled fleet-wide when
   * possible; when the fleet-wide compile refuses (e.g. a Mac-scoped app rule on Linux), it is skipped with the
   * reason: nobody would receive it, and a device of that platform enrolled later waits for a retarget that compiles
   * for it. Nothing is ever compiled weaker to make it fit.
   */
  async compilePlan(source: string, grants: unknown[], checkTargeted = true): Promise<{ platforms: ("linux" | "macos" | "dns")[]; targets: Partial<Record<"linux" | "macos" | "dns", string[]>>; skipped: { platform: string; reason: string }[]; failed: string[] }> {
    const targets = this.platformTargets();
    const platforms: ("linux" | "macos" | "dns")[] = [];
    const skipped: { platform: string; reason: string }[] = [];
    const failed: string[] = [];
    for (const p of this.platformsNeeded()) {
      const devs = targets[p] ?? [];
      if (devs.length && !checkTargeted) {
        platforms.push(p); // the signer compiles it and refuses the whole publication if it fails
        continue;
      }
      const c = await this.moatctl.compile(source, p, 1, this.now(), null, grants, devs);
      if (c.ok) platforms.push(p);
      else if (devs.length) failed.push(`${p} (devices ${devs.join(", ")}): ${c.error}`);
      else skipped.push({ platform: p, reason: `no enrolled ${p} devices and the fleet-wide ${p} compile refuses: ${c.error}` });
    }
    return { platforms, targets, skipped, failed };
  }

  /** Device list a stored snapshot was compiled for ([] = fleet-wide). */
  private snapshotTargets(signed: string): string[] {
    const s = JSON.parse(signed) as { payload: string };
    return (JSON.parse(Buffer.from(s.payload, "base64").toString("utf8")) as { devices?: string[] }).devices ?? [];
  }

  /**
   * Enrolled devices the current revision has no snapshot for: their platform's snapshot was compiled for a device
   * list made before they enrolled. They receive nothing (a targeted snapshot would be refused, correctly) until a
   * retarget publication names them.
   */
  untargetedDevices(): { device_id: string; platform: string; revision: number }[] {
    const cur = this.currentRevision();
    if (!cur) return [];
    const out: { device_id: string; platform: string; revision: number }[] = [];
    for (const d of this.db.prepare("SELECT id, platform FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string; platform: string }[]) {
      const row = this.db.prepare("SELECT signed FROM snapshots WHERE revision = ? AND platform = ?").get(cur.revision, platformAdapter(d.platform)) as { signed: string } | undefined;
      if (!row) {
        out.push({ device_id: d.id, platform: d.platform, revision: cur.revision });
        continue;
      }
      const t = this.snapshotTargets(row.signed);
      if (t.length && !t.includes(d.id)) out.push({ device_id: d.id, platform: d.platform, revision: cur.revision });
    }
    return out;
  }

  /**
   * Re-publish the current base and carried grants for the current device lists, so newly enrolled devices get a
   * snapshot that names them. The policy is unchanged, so the signer authorizes it as non-broadening; it never
   * carries a broadening change and never renews a grant (grants keep their own deadlines).
   */
  async retarget(actor: Principal) {
    this.require(actor, "owner");
    const missing = this.untargetedDevices();
    const cur = this.currentRevision();
    if (!cur || missing.length === 0) return { retargeted: false, missing: [] as string[] };
    const out = await this.publish(actor, cur.source, `retarget:${missing.map((m) => m.device_id).join(",")}`, {});
    audit(this.db, this.now(), actor.id, "policy.retarget", String(out.revision), { devices: missing.map((m) => m.device_id) });
    return { retargeted: true, revision: out.revision, missing: missing.map((m) => m.device_id) };
  }

  /** The policy a platform's endpoints evaluate for a revision (core-compiled: unsupported rules removed, grants rendered). */
  effectivePolicy(revision: number, platform: "linux" | "macos" | "dns"): string | null {
    const row = this.db.prepare("SELECT signed FROM snapshots WHERE revision = ? AND platform = ?").get(revision, platform) as { signed: string } | undefined;
    if (!row) return null;
    const signed = JSON.parse(row.signed) as { payload: string };
    return JSON.stringify((JSON.parse(Buffer.from(signed.payload, "base64").toString("utf8")) as { policy: unknown }).policy);
  }

  /** Was this rule omitted from a platform's compiled snapshot for a revision (its selector cannot be enforced there)? */
  omittedOn(revision: number, platform: string, ruleId: string): string | null {
    const row = this.db.prepare("SELECT report FROM snapshots WHERE revision = ? AND platform = ?").get(revision, platformAdapter(platform)) as { report: string } | undefined;
    if (!row) return null;
    const o = ((JSON.parse(row.report) as { omitted?: { rule_id: string; reason?: string; missing?: string[] }[] }).omitted ?? []).find((x) => x.rule_id === ruleId);
    return o ? (o.reason ?? (o.missing?.length ? `missing ${o.missing.join(", ")}` : "omitted by the compiler")) : null;
  }

  /** The canonical digest every grant binds as `base_policy_digest` (contracts/README.md; Rust `policy_digest`). */
  async baseDigest(base: string): Promise<{ digest: string; normalized: { profiles?: { id: string }[] } }> {
    const norm = await this.moatctl.run(["normalize", "@p.toml"], { "p.toml": base });
    if (norm.code !== 0) throw new HttpError(422, `base policy invalid: ${(norm.stderr || norm.stdout).trim()}`);
    const normalized = JSON.parse(norm.stdout) as { profiles?: { id: string }[] };
    return { digest: policyDigest(normalized), normalized };
  }

  /** Serialized publication: one signer request at a time, in revision order. */
  private publishChain: Promise<unknown> = Promise.resolve();
  private serialized<T>(f: () => Promise<T>): Promise<T> {
    const run = this.publishChain.then(f, f);
    this.publishChain = run.catch(() => undefined);
    return run;
  }

  /**
   * Build base + grant overlay, journal the publication, have the signer authorize and sign it, store the revision.
   * A lost signer reply leaves the journal row "uncertain"; recoverPublications() asks the signer for that
   * publication id and commits the same revision, so a retry never produces a conflicting one.
   */
  private publish(actor: Principal, base: string, subject: string, opts: { proposalId?: string; rollbackOf?: number | null; ownerAuthorization?: OwnerAuthorization | null; ownerSessionAttested?: boolean; grantApprovals?: GrantApproval[]; includeGrant?: string }) {
    return this.serialized(async () => {
      await this.recoverPublications();
      const rows = this.activeGrants();
      if (opts.includeGrant) {
        const g = this.db.prepare("SELECT * FROM grants WHERE id = ?").get(opts.includeGrant) as Record<string, unknown> | undefined;
        if (g && !rows.some((x) => x.id === g.id)) rows.push(g);
      }
      const { digest, normalized } = await this.baseDigest(base);
      // a grant was approved against one exact base policy: it is carried only while that base is current
      const carried = rows.filter((r) => r.grant_json && (JSON.parse(String(r.grant_json)) as GrantV1).base_policy_digest === digest);
      if (opts.includeGrant && !carried.some((r) => r.id === opts.includeGrant)) throw new HttpError(409, "stale: the base policy changed since this grant was approved; review it again");
      const superseded = rows.filter((r) => !carried.includes(r)).map((r) => String(r.id));
      const grants = carried.map((r) => JSON.parse(String(r.grant_json)) as GrantV1);
      const revision = (this.currentRevision()?.revision ?? 0) + 1;
      const profiles = (normalized.profiles ?? []).map((p) => p.id);
      const pubId = id("pub");
      const plan = await this.compilePlan(base, grants, false);
      if (plan.failed.length) throw new HttpError(422, `does not compile for this fleet: ${plan.failed.join("; ")}`);
      if (plan.platforms.length === 0) throw new HttpError(422, `does not compile for any platform: ${plan.skipped.map((x) => x.reason).join("; ")}`);
      const { platforms, targets, skipped } = plan;
      const intent = { revision, subject, base, grants: grants.map((g) => g.grant_id), superseded, profiles, proposal_id: opts.proposalId ?? null, rollback_of: opts.rollbackOf ?? null, actor: actor.id, owner_key_id: opts.ownerAuthorization?.key_id ?? null, platforms, targets, skipped };
      this.db.prepare("INSERT INTO publications (id, revision, subject, status, intent, created_at) VALUES (?, ?, ?, 'signing', ?, ?)").run(pubId, revision, subject, JSON.stringify(intent), this.iso());
      let res: SignResult;
      try {
        res = await this.signer.sign({ publicationId: pubId, subject, source: base, grants, revision, rollbackOf: opts.rollbackOf ?? null, platforms, targets, ownerAuthorization: opts.ownerAuthorization ?? null, ownerSessionAttested: opts.ownerSessionAttested ?? false, grantApprovals: opts.grantApprovals, issuedAt: this.now() });
      } catch (e) {
        const st = (e as { status?: number }).status;
        // a refusal is final (nothing was signed); anything else may have been signed: keep it for recovery
        this.db.prepare("UPDATE publications SET status = ?, error = ?, finished_at = ? WHERE id = ?").run(st && st < 500 ? "refused" : "uncertain", String((e as Error).message).slice(0, 500), this.iso(), pubId);
        throw e;
      }
      this.commitPublication(pubId, intent, res);
      return { revision, publication_id: pubId, authorized_by: res.authorizedBy, broadening: res.broadening, effective_digest: res.effective_digest ?? null, superseded_grants: superseded, platforms: res.snapshots.map((s) => ({ platform: s.platform, report: s.report })), skipped_platforms: skipped };
    });
  }

  private commitPublication(pubId: string, intent: { revision: number; subject: string; base: string; grants: string[]; superseded?: string[]; profiles: string[]; proposal_id: string | null; rollback_of: number | null; actor: string; owner_key_id: string | null }, res: SignResult) {
    // the effective policy is what the core compiled (base + exact grant rules), read back from the signed snapshot
    const snap = res.snapshots.find((s) => s.platform === "linux") ?? res.snapshots[0];
    const effective = snap ? JSON.stringify((JSON.parse(Buffer.from(snap.signed.payload, "base64").toString("utf8")) as { policy: unknown }).policy) : intent.base;
    tx(this.db, () => {
      this.db.prepare("INSERT INTO policy_revisions (revision, proposal_id, source, source_digest, effective_source, rollback_of, grants, profiles, approved_by, owner_key_id, created_at, authorized_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(intent.revision, intent.proposal_id, intent.base, sha256hex(intent.base), effective, intent.rollback_of, JSON.stringify(intent.grants), JSON.stringify(intent.profiles), intent.actor, res.authorizedBy === "owner_key" ? intent.owner_key_id : null, this.iso(), res.authorizedBy);
      for (const s of res.snapshots) this.db.prepare("INSERT INTO snapshots (revision, platform, signed, report) VALUES (?, ?, ?, ?)").run(intent.revision, s.platform, JSON.stringify(s.signed), JSON.stringify(s.report));
      for (const d of this.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").all() as { id: string }[]) this.recordRevisionState(d.id, intent.revision, "approved", null);
      for (const g of intent.grants) this.db.prepare("UPDATE grants SET revision = COALESCE(revision, ?), committed = 1, authorized_by = COALESCE(authorized_by, ?) WHERE id = ?").run(intent.revision, res.authorizedBy, g);
      for (const g of intent.superseded ?? []) this.db.prepare("UPDATE grants SET revoked_at = ?, ended_reason = ? WHERE id = ? AND revoked_at IS NULL").run(this.iso(), `superseded: revision ${intent.revision} changed the base policy it was approved against`, g);
      if (intent.proposal_id) this.db.prepare("UPDATE policy_proposals SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ? AND status = 'open'").run(this.iso(), intent.actor, intent.proposal_id);
      this.db.prepare("UPDATE publications SET status = 'committed', finished_at = ?, error = NULL WHERE id = ?").run(this.iso(), pubId);
    });
    audit(this.db, this.now(), intent.actor, "policy.publish", String(intent.revision), { subject: intent.subject, publication: pubId, authorized_by: res.authorizedBy, issuers: res.issuers ?? [], broadening: res.broadening, grants: intent.grants.length, superseded: intent.superseded ?? [], effective_digest: res.effective_digest ?? null });
  }

  /**
   * Reconcile journaled publications whose outcome is unknown (crash or lost reply): commit what the signer signed,
   * abandon what it never signed. Runs at startup and before every publication.
   */
  async recoverPublications() {
    const rows = this.db.prepare("SELECT id, intent FROM publications WHERE status IN ('signing', 'uncertain') ORDER BY rowid").all() as { id: string; intent: string }[];
    const out: { id: string; outcome: string }[] = [];
    for (const r of rows) {
      if (!this.signer.publication) {
        out.push({ id: r.id, outcome: "unknown (signer has no journal API)" });
        continue;
      }
      const res = await this.signer.publication(r.id);
      const intent = JSON.parse(r.intent) as Parameters<Controller["commitPublication"]>[1];
      if (res && !this.db.prepare("SELECT 1 FROM policy_revisions WHERE revision = ?").get(intent.revision)) {
        this.commitPublication(r.id, intent, res);
        out.push({ id: r.id, outcome: `recovered revision ${intent.revision}` });
      } else if (res) {
        this.db.prepare("UPDATE publications SET status = 'conflict', finished_at = ? WHERE id = ?").run(this.iso(), r.id);
        out.push({ id: r.id, outcome: "conflict: revision already stored" });
      } else {
        this.db.prepare("UPDATE publications SET status = 'abandoned', finished_at = ? WHERE id = ?").run(this.iso(), r.id);
        out.push({ id: r.id, outcome: "abandoned: never signed" });
      }
    }
    return out;
  }

  publications() {
    return this.db.prepare("SELECT id, revision, subject, status, error, created_at, finished_at FROM publications ORDER BY rowid DESC LIMIT 50").all();
  }

  async approve(actor: Principal, pid: string, ownerAuthorization?: OwnerAuthorization | null) {
    this.require(actor, "owner");
    const p = this.db.prepare("SELECT * FROM policy_proposals WHERE id = ? AND status = 'open'").get(pid) as { id: string; source: string; rollback_of: number | null; base_revision: number | null } | undefined;
    if (!p) throw new HttpError(404, "no open proposal with that id");
    const cur = this.currentRevision();
    if ((cur?.revision ?? null) !== p.base_revision) throw new HttpError(409, `proposal was prepared against revision ${p.base_revision}; current is ${cur?.revision}. Prepare it again.`);
    let out;
    try {
      out = await this.publish(actor, p.source, pid, { proposalId: pid, rollbackOf: p.rollback_of, ownerAuthorization });
    } catch (e) {
      const err = e as { status?: number; message?: string };
      throw new HttpError(err.status ?? 500, err.message ?? String(e));
    }
    return out;
  }

  /** A rollback is a new, newly authorized revision whose content is an older one's. */
  async rollback(actor: Principal, toRevision: number, message = "") {
    this.require(actor, "owner");
    const old = this.db.prepare("SELECT source FROM policy_revisions WHERE revision = ?").get(toRevision) as { source: string } | undefined;
    if (!old) throw new HttpError(404, "no such revision");
    return this.propose(actor, old.source, message || `Roll back to revision ${toRevision}`, toRevision);
  }

  revisions() {
    const revs = this.db.prepare("SELECT revision, proposal_id, source_digest, rollback_of, grants, approved_by, owner_key_id, authorized_by, created_at FROM policy_revisions ORDER BY revision DESC LIMIT 50").all() as { revision: number; proposal_id: string | null; source_digest: string; rollback_of: number | null; grants: string; approved_by: string; owner_key_id: string | null; authorized_by: string | null; created_at: string }[];
    return revs.map((r) => ({
      ...r,
      message: r.proposal_id ? ((this.db.prepare("SELECT message FROM policy_proposals WHERE id = ?").get(r.proposal_id) as { message: string } | undefined)?.message ?? null) : null,
      grants: JSON.parse(String(r.grants)),
      devices: this.db.prepare("SELECT device_id, state, at, detail FROM device_revisions WHERE revision = ? ORDER BY device_id, at").all(Number(r.revision)),
      platforms: this.db.prepare("SELECT platform, report FROM snapshots WHERE revision = ?").all(Number(r.revision)).map((s) => ({ platform: (s as { platform: string }).platform, report: JSON.parse((s as { report: string }).report) })),
    }));
  }

  // ------------------------------------------------------------------ temporary grants
  /**
   * Turn a grant request into an exact plan: a `moat.grant.v1` object (one device, one task or one app, one
   * destination, one transport and port, a deadline fixed now, the digest of the current base policy, the issuer who
   * will approve it) plus the approval context (kind, incident, policy revision). Idempotency follows the core's
   * GrantLedger: the same key and the same request return the original plan (or the grant it became) with its
   * original deadline; the same key with a different request is refused.
   */
  async planGrant(actor: Principal, b: { kind?: string; device_id?: unknown; session_id?: unknown; boot_id?: unknown; process_instance?: unknown; app_executable?: unknown; destination?: unknown; transport?: unknown; port?: unknown; ttl_seconds?: unknown; reason?: unknown; incident?: { id: string; revision: number } | null; operation_id?: unknown; issuer_key_id?: unknown }) {
    this.require(actor, "owner");
    const cur = this.currentRevision();
    if (!cur) throw new HttpError(409, "no policy revision exists yet");
    const kind: ApprovalContext["kind"] = b.kind === "allow_once" ? "allow_once" : "temporary";
    const opKey = typeof b.operation_id === "string" && /^[A-Za-z0-9:._-]{8,120}$/.test(b.operation_id) ? b.operation_id : b.incident ? `incident:${b.incident.id}:r${b.incident.revision}:p${cur.revision}:${kind}` : null;
    if (!opKey) throw new HttpError(400, "operation_id (8-120 chars of [A-Za-z0-9:._-]) is required for a grant not tied to an incident");
    if (b.process_instance !== undefined && b.process_instance !== null) throw new HttpError(422, "process-scoped grants are unavailable: no endpoint enforces a process-generation selector yet");
    const ttl = Math.min(ALLOW_ONCE_MAX_SECONDS, Math.max(60, Math.round(Number(b.ttl_seconds ?? ALLOW_ONCE_DEFAULT_SECONDS))));
    const issuerKey = typeof b.issuer_key_id === "string" && b.issuer_key_id ? b.issuer_key_id : null;
    const request = { kind, device_id: b.device_id ?? null, session_id: b.session_id ?? null, boot_id: b.boot_id ?? null, app_executable: b.app_executable ?? null, destination: b.destination ?? null, transport: b.transport === "udp" ? "udp" : "tcp", port: b.port ?? null, ttl_seconds: ttl, incident: b.incident ?? null, issuer_key_id: issuerKey };
    const requestDigest = sha256hex(canonicalJson(request));
    const existing = this.db.prepare("SELECT * FROM grant_plans WHERE idempotency_key = ?").get(opKey) as PlanRow | undefined;
    if (existing) {
      if (existing.created_by !== actor.id) throw new HttpError(409, "this operation id belongs to another principal");
      if (existing.request_digest !== requestDigest) throw new HttpError(409, "this operation id was already used for a different request");
      return this.planView(existing);
    }
    const device = typeof b.device_id === "string" ? b.device_id : "";
    if (!this.db.prepare("SELECT 1 FROM devices WHERE id = ? AND revoked_at IS NULL").get(device)) throw new HttpError(400, "a grant must name one enrolled device (device_id)");
    const dest = String(b.destination ?? "");
    const isAddr = isIP(dest) !== 0;
    if (!isAddr && !/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(dest)) throw new HttpError(400, "destination must be one IP address or one hostname");
    const port = Number(b.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(400, "port must be 1-65535");
    const session = typeof b.session_id === "string" && b.session_id ? b.session_id : null;
    const exe = typeof b.app_executable === "string" && b.app_executable.startsWith("/") ? b.app_executable : null;
    if (!session && !exe) throw new HttpError(400, "a grant must be scoped to a session or an application");
    if (session && exe) throw new HttpError(400, "a grant is scoped to a session or an application, not both");
    if (session && !/^[a-z0-9-]{1,64}$/.test(session)) throw new HttpError(400, "invalid session id");
    const boot = typeof b.boot_id === "string" && /^[A-Za-z0-9_.:@/-]{1,128}$/.test(b.boot_id) ? b.boot_id : null;
    if (session && !boot) throw new HttpError(422, "a task grant needs the device's boot id (from the incident's process evidence); none was recorded");
    let issuer: GrantV1["issuer"] = { principal: principalId(`owner:${actor.id}`), role: "owner" };
    if (issuerKey) {
      const del = this.db.prepare("SELECT label FROM issuers WHERE key_id = ? AND revoked_at IS NULL").get(issuerKey) as { label: string } | undefined;
      if (!del) throw new HttpError(403, "unknown or revoked issuer");
      issuer = { principal: principalId(`issuer:${issuerKey}`), role: "delegated", key_id: issuerKey };
    }
    const now = this.now();
    const issued = contractTime(now);
    const context: ApprovalContext = { schema: "moat.grant_context.v1", kind, policy_revision: cur.revision, requested_by: principalId(actor.id), ...(b.incident ? { incident: b.incident } : {}) };
    const { digest: baseDigest } = await this.baseDigest(cur.source);
    const reason = String(b.reason ?? "").slice(0, 200);
    const grant: GrantV1 = {
      schema: "moat.grant.v1",
      grant_id: `grant-${token(9).toLowerCase().replace(/[^a-z0-9]/g, "x")}`,
      idempotency_key: opKey,
      scope: session ? { kind: "task", device_id: device, boot_id: boot!, task_id: session } : { kind: "app_on_device", device_id: device, executable: { path: exe! } },
      destination: isAddr ? { kind: "address", address: dest } : { kind: "hostname", hostname: dest },
      transport: request.transport as "tcp" | "udp",
      port,
      issued_at: issued,
      not_before: issued,
      admission_until: contractTime(new Date(Date.parse(issued) + ttl * 1000)),
      stream_policy: "admission_only",
      base_policy_digest: baseDigest,
      issuer,
      approval_digest: contextDigest(context),
      ...(reason ? { reason } : {}),
    };
    const pid = id("plan");
    const digest = grantDigest(grant);
    this.db.prepare("INSERT INTO grant_plans (id, idempotency_key, plan, digest, policy_revision, created_by, created_at, expires_at, request_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(pid, opKey, JSON.stringify({ grant, context }), digest, cur.revision, actor.id, this.iso(), new Date(now.getTime() + PLAN_VALID_MS).toISOString(), requestDigest);
    audit(this.db, now, actor.id, "grant.plan", pid, { grant_id: grant.grant_id, digest });
    return this.planView(this.db.prepare("SELECT * FROM grant_plans WHERE id = ?").get(pid) as unknown as PlanRow);
  }

  private planView(r: PlanRow) {
    const { grant, context } = JSON.parse(r.plan) as { grant: GrantV1; context: ApprovalContext };
    return { plan_id: r.id, plan: grant, context, kind: context.kind, digest: r.digest, approval_expires_at: r.expires_at, grant_id: r.grant_id, signing_string: `moat-grant-approval-v1\n${r.digest}\n`, committed: !!r.grant_id };
  }

  /**
   * Commit an approved plan: re-check that nothing it was based on has changed, store the grant with the plan's
   * original deadline and publish. Committing the same plan again returns the original grant.
   */
  async commitGrant(actor: Principal, b: { plan_id?: unknown; issuer_key_id?: unknown; issuer_signature?: unknown }) {
    this.require(actor, "owner");
    const row = this.db.prepare("SELECT * FROM grant_plans WHERE id = ?").get(String(b.plan_id ?? "")) as PlanRow | undefined;
    if (!row) throw new HttpError(404, "no such grant plan");
    if (row.created_by !== actor.id) throw new HttpError(403, "this plan was prepared for another principal");
    if (row.grant_id) return { ...this.grantResult(row.grant_id), idempotent_replay: true };
    if (row.expires_at <= this.iso()) throw new HttpError(409, "stale: this plan's approval window passed; review it again");
    const { grant: g, context } = JSON.parse(row.plan) as { grant: GrantV1; context: ApprovalContext };
    const cur = this.currentRevision();
    if (!cur || cur.revision !== row.policy_revision) throw new HttpError(409, `stale: policy is now revision ${cur?.revision}; review again`);
    if (context.incident) {
      const inc = this.db.prepare("SELECT revision FROM incidents WHERE id = ?").get(context.incident.id) as { revision: number } | undefined;
      if (!inc || inc.revision !== context.incident.revision) throw new HttpError(409, "stale: the incident changed since this action was offered; review it again");
    }
    if (g.scope.kind === "task") {
      const sess = this.db.prepare("SELECT state FROM sessions WHERE device_id = ? AND id = ?").get(g.scope.device_id, g.scope.task_id ?? "") as { state: string } | undefined;
      if (!sess || sess.state !== "running") throw new HttpError(409, "stale: that session is no longer running");
    }
    let approvals: GrantApproval[] | undefined;
    let issuer: string | null = null;
    if (b.issuer_signature !== undefined) {
      if (g.issuer.role !== "delegated" || g.issuer.key_id !== String(b.issuer_key_id ?? "")) throw new HttpError(409, "this plan names a different approver; prepare it again with this device's issuer_key_id");
      const del = this.db.prepare("SELECT delegation FROM issuers WHERE key_id = ? AND revoked_at IS NULL").get(String(b.issuer_key_id ?? "")) as { delegation: string } | undefined;
      if (!del) throw new HttpError(403, "unknown or revoked issuer");
      approvals = [{ grant_id: g.grant_id, context, delegation: JSON.parse(del.delegation) as Delegation, issuer_signature: String(b.issuer_signature) }];
      issuer = String(b.issuer_key_id);
    } else if (g.issuer.role === "delegated") throw new HttpError(400, "this plan is to be approved by a delegated issuer: send issuer_key_id and issuer_signature");
    const target = g.scope;
    const auditId = audit(this.db, this.now(), actor.id, "grant.create", g.grant_id, { plan: row.id, digest: row.digest, issuer });
    this.db.prepare("INSERT INTO grants (id, kind, device_id, session_id, profile, process_instance, destination, transport, port, expires_at, reason, incident_id, created_by, created_at, boot_id, plan_id, plan_digest, issuer_key_id, committed, grant_json) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)")
      .run(g.grant_id, context.kind, target.device_id, target.kind === "task" ? target.task_id! : null, target.kind === "app_on_device" ? target.executable?.path ?? null : null, g.destination.kind === "address" ? g.destination.address : g.destination.hostname, g.transport, g.port, new Date(g.admission_until).toISOString(), `${g.reason ?? ""}|audit:${auditId}`, context.incident?.id ?? null, actor.id, this.iso(), target.kind === "task" ? target.boot_id ?? null : null, row.id, row.digest, issuer, JSON.stringify(g));
    try {
      await this.publish(actor, cur.source, g.grant_id, { ownerSessionAttested: !approvals && actor.role === "owner", grantApprovals: approvals, includeGrant: g.grant_id });
    } catch (e) {
      // nothing was signed for this grant (or the outcome is journaled for recovery): it never becomes active by retry
      const pub = this.db.prepare("SELECT status FROM publications WHERE subject = ? ORDER BY rowid DESC LIMIT 1").get(g.grant_id) as { status: string } | undefined;
      if (pub?.status !== "uncertain") this.db.prepare("DELETE FROM grants WHERE id = ? AND committed = 0").run(g.grant_id);
      const err = e as { status?: number; message?: string };
      throw new HttpError(err.status ?? 500, err.message ?? String(e));
    }
    this.db.prepare("UPDATE grant_plans SET grant_id = ? WHERE id = ?").run(g.grant_id, row.id);
    return this.grantResult(g.grant_id);
  }

  private grantResult(gid: string) {
    const g = this.db.prepare("SELECT id, revision, expires_at, authorized_by, issuer_key_id FROM grants WHERE id = ?").get(gid) as { id: string; revision: number; expires_at: string; authorized_by: string; issuer_key_id: string | null };
    return { grant_id: g.id, revision: g.revision, expires_at: g.expires_at, authorized_by: g.authorized_by, issuer_key_id: g.issuer_key_id, delivery: "queued for devices; see GET /v1/grants/:id for received/applied" };
  }

  /** One-call grant through the controller-attested path (only if the signer allows it). Prefer plan + issuer signature. */
  async createGrant(actor: Principal, b: Parameters<Controller["planGrant"]>[1]) {
    const p = await this.planGrant(actor, b);
    return this.commitGrant(actor, { plan_id: p.plan_id });
  }

  async revokeGrant(actor: Principal, gid: string) {
    this.require(actor, "owner");
    const r = this.db.prepare("UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND committed = 1").run(this.iso(), gid);
    if (!r.changes) throw new HttpError(404, "no such active grant");
    audit(this.db, this.now(), actor.id, "grant.revoke", gid, null);
    const cur = this.currentRevision()!;
    return this.publish(actor, cur.source, `revoke:${gid}`, {});
  }

  grants(): (Record<string, unknown> & { id: string; state: string })[] {
    return (this.db.prepare("SELECT * FROM grants WHERE committed = 1 ORDER BY created_at DESC LIMIT 100").all() as (Record<string, unknown> & { id: string })[]).map((g) => ({ ...g, state: g.revoked_at ? "revoked" : String(g.expires_at) <= this.iso() ? "expired" : "active" }));
  }

  // ------------------------------------------------------------------ delegated issuers (phone approvals)
  /** Register an owner-signed delegation. The signer verifies it on every use; this only records it. */
  registerIssuer(actor: Principal, b: { delegation?: unknown }) {
    this.require(actor, "owner");
    const d = b.delegation as Delegation | undefined;
    if (!d || d.schema !== "moat.delegation.v1" || typeof d.issuer_public_hex !== "string" || typeof d.signature !== "string" || !Array.isArray(d.scope?.devices) || !Array.isArray(d.scope?.kinds)) throw new HttpError(400, "delegation must be a moat.delegation.v1 object from `moat-controller delegate-issuer`");
    try {
      publicFromHex(d.issuer_public_hex);
    } catch {
      throw new HttpError(400, "issuer_public_hex is not an Ed25519 public key");
    }
    if (keyIdOf(d.issuer_public_hex) !== d.issuer_key_id) throw new HttpError(400, "issuer key id does not match its public key");
    if (Date.parse(d.not_after) <= this.now().getTime()) throw new HttpError(400, "delegation already expired");
    this.db.prepare("INSERT OR REPLACE INTO issuers (key_id, label, delegation, registered_by, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)").run(d.issuer_key_id, String(d.label ?? "").slice(0, 80), JSON.stringify(d), actor.id, this.iso());
    audit(this.db, this.now(), actor.id, "issuer.register", d.issuer_key_id, { scope: d.scope, not_after: d.not_after });
    return { key_id: d.issuer_key_id, label: d.label, scope: d.scope, not_after: d.not_after };
  }
  issuers() {
    return (this.db.prepare("SELECT key_id, label, delegation, created_at, revoked_at FROM issuers ORDER BY created_at DESC").all() as { key_id: string; label: string; delegation: string; created_at: string; revoked_at: string | null }[]).map((r) => {
      const d = JSON.parse(r.delegation) as Delegation;
      return { key_id: r.key_id, label: r.label, scope: d.scope, not_after: d.not_after, created_at: r.created_at, revoked_at: r.revoked_at };
    });
  }
  revokeIssuer(actor: Principal, keyId: string) {
    this.require(actor, "owner");
    const r = this.db.prepare("UPDATE issuers SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL").run(this.iso(), keyId);
    if (!r.changes) throw new HttpError(404, "no such active issuer");
    audit(this.db, this.now(), actor.id, "issuer.revoke", keyId, null);
    return { revoked: keyId, note: "Registered delegations stop being offered by this controller now. The delegation itself stays valid at the signer until its not_after; rotate the owner key to cut it sooner." };
  }

  /**
   * The status of one grant, derived only from endpoint evidence: "active" needs an endpoint receipt for a revision
   * that carries the grant; a request, a signature or a delivery is "pending". Expiry and revocation are computed
   * here from the grant's original deadline, never extended by a later revision.
   */
  grantStatus(gid: string) {
    const g = this.db.prepare("SELECT * FROM grants WHERE id = ?").get(gid) as Record<string, unknown> | undefined;
    if (!g) throw new HttpError(404, "no such grant");
    const rev = g.revision === null || g.revision === undefined ? null : Number(g.revision);
    const targets = g.device_id ? [String(g.device_id)] : (this.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string }[]).map((r) => r.id);
    const devices = targets.map((deviceId) => {
      const dev = this.db.prepare("SELECT last_seen_at, coverage FROM devices WHERE id = ?").get(deviceId) as Pick<DeviceRow, "last_seen_at" | "coverage"> | undefined;
      const rows = rev === null ? [] : (this.db.prepare("SELECT revision, state, at, detail FROM device_revisions WHERE device_id = ? AND revision >= ? ORDER BY revision DESC, at DESC").all(deviceId, rev) as { revision: number; state: string; at: string; detail: string | null }[]);
      const latestApplied = rows.find((r) => r.state === "applied" || r.state === "confirmed" || r.state === "trial");
      const rolledBack = rows.find((r) => r.state === "rolled_back" && (!latestApplied || r.revision >= latestApplied.revision));
      const rejected = rows.find((r) => r.state === "rejected" && (!latestApplied || r.revision >= latestApplied.revision));
      const state = rolledBack ? "rolled_back" : rejected ? "rejected" : latestApplied ? (latestApplied.state === "trial" ? "trial" : "applied") : rows.some((r) => r.state === "received") ? "received" : rows.some((r) => r.state === "distributed") ? "delivered" : "queued";
      const evidence = rolledBack ?? rejected ?? latestApplied ?? rows[0] ?? null;
      const platform = (this.db.prepare("SELECT platform FROM devices WHERE id = ?").get(deviceId) as { platform: string } | undefined)?.platform ?? "linux";
      const omitted = rev === null ? null : this.omittedOn(rev, platform, String(g.id));
      if (omitted) return { device_id: deviceId, state: "not_enforceable", evidence, reason: `this device's platform cannot enforce the grant's scope (${omitted}); the compiler left it out, so nothing was allowed`, ...(dev ? this.staleness(dev) : { stale: true, effective_coverage: "unknown", coverage_note: "device revoked or unknown" }) };
      return { device_id: deviceId, state, evidence, ...(dev ? this.staleness(dev) : { stale: true, effective_coverage: "unknown", coverage_note: "device revoked or unknown" }) };
    });
    const now = this.iso();
    const expired = String(g.expires_at) <= now;
    const anyApplied = devices.some((d) => d.state === "applied" || d.state === "trial");
    const state = g.revoked_at ? "revoked" : expired ? "expired" : devices.length > 0 && devices.every((d) => d.state === "not_enforceable") ? "not_enforceable" : devices.some((d) => d.state === "rejected" || d.state === "rolled_back") && !anyApplied ? "rejected" : anyApplied ? "active" : "pending";
    return {
      id: String(g.id),
      kind: String(g.kind),
      state,
      device_id: g.device_id ?? null,
      session_id: g.session_id ?? null,
      destination: String(g.destination),
      transport: String(g.transport),
      port: g.port === null ? null : Number(g.port),
      created_at: String(g.created_at),
      created_by: String(g.created_by),
      expires_at: String(g.expires_at),
      revoked_at: g.revoked_at ?? null,
      ended_reason: g.ended_reason ?? null,
      revision: rev,
      authorized_by: rev === null ? null : ((this.db.prepare("SELECT authorized_by FROM policy_revisions WHERE revision = ?").get(rev) as { authorized_by: string | null } | undefined)?.authorized_by ?? null),
      incident_id: g.incident_id ?? null,
      devices,
      server_time: now,
      note: "active means an endpoint receipt names a revision that carries this grant; it is not independent proof of every packet verdict.",
    };
  }

  /**
   * "Allow once for this session": bound to the incident, the policy revision the owner saw, the incident's session
   * and process instance, and the authenticated owner. Rejected when stale (newer policy, ended session, a different
   * process instance than the one the notification described, or an incident that has changed since).
   */
  /** Validate an allow-once request against current evidence and return the exact plan to approve. */
  async planAllowOnce(actor: Principal, b: { incident_id?: unknown; incident_revision?: unknown; policy_revision?: unknown; ttl_seconds?: unknown; operation_id?: unknown; issuer_key_id?: unknown }) {
    this.require(actor, "owner");
    // a retried operation is answered with its original plan (or grant) before anything newer can make it "stale";
    // the same operation id for a different request is refused (GrantLedger semantics)
    if (typeof b.operation_id === "string") {
      const prior = this.db.prepare("SELECT * FROM grant_plans WHERE idempotency_key = ?").get(b.operation_id) as PlanRow | undefined;
      if (prior) {
        if (prior.created_by !== actor.id) throw new HttpError(409, "this operation id belongs to another principal");
        const view = this.planView(prior);
        const ttl = Math.min(ALLOW_ONCE_MAX_SECONDS, Math.max(60, Math.round(Number(b.ttl_seconds ?? ALLOW_ONCE_DEFAULT_SECONDS))));
        const same = view.context.incident?.id === String(b.incident_id ?? "") && view.context.incident?.revision === Number(b.incident_revision) && (Date.parse(view.plan.admission_until) - Date.parse(view.plan.issued_at)) / 1000 === ttl && (view.plan.issuer.key_id ?? null) === (typeof b.issuer_key_id === "string" && b.issuer_key_id ? b.issuer_key_id : null);
        if (!same) throw new HttpError(409, "this operation id was already used for a different request");
        return view;
      }
    }
    const inc = this.db.prepare("SELECT * FROM incidents WHERE id = ?").get(String(b.incident_id ?? "")) as unknown as IncidentRow | undefined;
    if (!inc) throw new HttpError(404, "no such incident");
    if (inc.kind !== "blocked_connection" || !inc.session_id) throw new HttpError(422, "allow once applies to a blocked connection from a verified protected session");
    if (Number(b.incident_revision) !== inc.revision) throw new HttpError(409, "stale: the incident changed since this action was offered; review it again");
    const cur = this.currentRevision();
    if (!cur || Number(b.policy_revision) !== cur.revision) throw new HttpError(409, `stale: policy is now revision ${cur?.revision}; review again`);
    const sess = this.db.prepare("SELECT * FROM sessions WHERE device_id = ? AND id = ?").get(inc.device_id, inc.session_id) as { state: string } | undefined;
    if (!sess || sess.state !== "running") throw new HttpError(409, "stale: that session is no longer running");
    if (!inc.port || inc.destination === "rule-scoped") throw new HttpError(422, "this platform did not record the destination; create a reviewed policy change instead");
    const boot = inc.process_instance?.split("/")[1] || null;
    return this.planGrant(actor, { kind: "allow_once", device_id: inc.device_id, session_id: inc.session_id, boot_id: boot, destination: inc.destination, transport: inc.transport ?? "tcp", port: inc.port, ttl_seconds: b.ttl_seconds ?? ALLOW_ONCE_DEFAULT_SECONDS, reason: `allow once for incident ${inc.id}`, incident: { id: inc.id, revision: inc.revision }, operation_id: b.operation_id, issuer_key_id: b.issuer_key_id });
  }

  /**
   * "Allow once for this session", one call: plan + commit through the controller-attested path. The signer only
   * honors that path when started with controller-attested grants; otherwise use plan + a delegated issuer signature.
   */
  async allowOnce(actor: Principal, b: { incident_id?: unknown; incident_revision?: unknown; policy_revision?: unknown; ttl_seconds?: unknown; operation_id?: unknown; plan_id?: unknown; issuer_key_id?: unknown; issuer_signature?: unknown }) {
    this.require(actor, "owner");
    if (b.plan_id !== undefined) return this.commitGrant(actor, b);
    const p = await this.planAllowOnce(actor, { ...b, issuer_key_id: undefined });
    if (p.grant_id) return { ...this.grantResult(p.grant_id), idempotent_replay: true };
    return this.commitGrant(actor, { plan_id: p.plan_id });
  }


  // ------------------------------------------------------------------ Harness / Dispatch launch API
  /** Profiles a device can launch now: defined in the current policy and not unavailable on its platform. */
  launchProfiles(deviceId: string) {
    const d = this.db.prepare("SELECT platform, capabilities FROM devices WHERE id = ? AND revoked_at IS NULL").get(deviceId) as { platform: string; capabilities: string | null } | undefined;
    if (!d) throw new HttpError(404, "no such device");
    const cur = this.currentRevision();
    const snap = cur ? (this.db.prepare("SELECT report FROM snapshots WHERE revision = ? AND platform = ?").get(cur.revision, platformAdapter(d.platform)) as { report: string } | undefined) : undefined;
    const unavailable = snap ? ((JSON.parse(snap.report) as { unavailable_session_profiles?: string[] }).unavailable_session_profiles ?? []) : [];
    const caps = d.capabilities ? (JSON.parse(d.capabilities) as { capabilities?: Record<string, { support: string }> }) : null;
    const sessionSupport = caps?.capabilities?.session_enforcement?.support ?? "unknown";
    const profRow = cur ? (this.db.prepare("SELECT profiles FROM policy_revisions WHERE revision = ?").get(cur.revision) as { profiles: string } | undefined) : undefined;
    const profiles = profRow ? (JSON.parse(profRow.profiles) as string[]) : [];
    return {
      device_id: deviceId,
      revision: cur?.revision ?? null,
      session_enforcement: sessionSupport,
      profiles: sessionSupport === "unsupported" ? [] : profiles.filter((p) => !unavailable.includes(p)),
      unavailable,
      launch: "Run on the device: moat-launch --profile <profile> -- <command>. The endpoint creates the boundary before exec and returns the session id; this API never launches anything itself.",
    };
  }

  sessions(deviceId?: string) {
    return deviceId ? this.db.prepare("SELECT * FROM sessions WHERE device_id = ? ORDER BY started_at DESC LIMIT 100").all(deviceId) : this.db.prepare("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 100").all();
  }

  /** Agent self-report: enrichment only. Origin runtime_self_report may assert intent and nothing else. */
  reportIntent(actor: Principal, deviceId: string, sessionId: string, b: { assertion?: unknown; text?: unknown }) {
    this.require(actor, "agent", "launcher", "owner");
    const assertion = String(b.assertion ?? "intent");
    if (assertion !== "intent") throw new HttpError(403, `a runtime self-report may only assert intent; "${assertion}" needs endpoint or launcher evidence`);
    const text = String(b.text ?? "").slice(0, 280);
    const r = this.db.prepare("UPDATE sessions SET intent = ? WHERE device_id = ? AND id = ?").run(JSON.stringify({ text, origin: "runtime_self_report", by: actor.id, at: this.iso() }), deviceId, sessionId);
    if (!r.changes) throw new HttpError(404, "no such session (sessions are created by the endpoint, not by self-report)");
    return { recorded: true, origin: "runtime_self_report", note: "Self-reported intent enriches the timeline. It cannot grant access, sign policy, corroborate evidence or report a block." };
  }

  requestClose(actor: Principal, deviceId: string, sessionId: string) {
    this.require(actor, "owner", "launcher");
    const s = this.db.prepare("SELECT state FROM sessions WHERE device_id = ? AND id = ?").get(deviceId, sessionId) as { state: string } | undefined;
    if (!s) throw new HttpError(404, "no such session");
    const aid = id("act");
    this.db.prepare("INSERT INTO device_actions (id, device_id, kind, args, created_at) VALUES (?, ?, 'close_session', ?, ?)").run(aid, deviceId, JSON.stringify({ session_id: sessionId }), this.iso());
    this.db.prepare("UPDATE sessions SET close_requested_at = ? WHERE device_id = ? AND id = ?").run(this.iso(), deviceId, sessionId);
    audit(this.db, this.now(), actor.id, "session.close_request", `${deviceId}/${sessionId}`, null);
    return { action_id: aid, state: "queued", note: "Delivered on the device's next sync; closed when the endpoint reports session_ended." };
  }

  /** Never claim more than the last report supports: a stale or silent device shows degraded / unknown. */
  staleness(d: Pick<DeviceRow, "last_seen_at" | "coverage">) {
    if (!d.last_seen_at) return { stale: true, effective_coverage: "unknown", coverage_note: "This device has not reported since enrollment." };
    const age = this.now().getTime() - Date.parse(d.last_seen_at);
    if (age > STALE_AFTER_MS) {
      return { stale: true, effective_coverage: "degraded", coverage_note: `No report for ${Math.round(age / 60_000)} minutes; the last known policy may still be enforced locally, but Moat cannot confirm it.` };
    }
    return { stale: false, effective_coverage: d.coverage ?? "unknown", coverage_note: null };
  }

  // ------------------------------------------------------------------ overview
  overview() {
    const devices = this.devices();
    const open = this.db.prepare("SELECT COUNT(*) AS n FROM incidents WHERE state = 'open'").get() as { n: number };
    return {
      server_time: this.iso(),
      revision: this.currentRevision()?.revision ?? null,
      devices: devices.map((d) => ({ id: d.id, name: d.name, platform: d.platform, coverage: d.coverage, effective_coverage: d.effective_coverage, stale: d.stale, last_seen_at: d.last_seen_at, last_revision: d.last_revision })),
      open_incidents: open.n,
      active_grants: this.activeGrants().length,
      retention: this.flows.retention(),
      notifications: this.notifier.status(),
    };
  }
}

/** A contract id ([A-Za-z0-9-_.:@/]{1,128}) from free text. */
function principalId(s: string): string {
  return s.replace(/[^A-Za-z0-9_.:@/-]/g, "_").slice(0, 128) || "unknown";
}

interface PlanRow { id: string; idempotency_key: string; plan: string; digest: string; policy_revision: number; created_by: string; created_at: string; expires_at: string; grant_id: string | null; request_digest: string | null }
