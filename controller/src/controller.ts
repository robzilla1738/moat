/**
 * The Moat controller: enrollment, device sync, policy proposals and revisions, the temporary-grant overlay, bounded
 * "Allow once for this session" actions, incidents (attention queue), the Harness/Dispatch launch API and DNS-only
 * clients. It coordinates; it never sits in the traffic path, never signs (see signer.ts) and never sends shell
 * commands to endpoints — device actions are a closed set of typed operations.
 */
import { isIP } from "node:net";
import { audit, CONTROL_MIGRATIONS, HttpError, openDb, tx, type DB } from "./db.ts";
import { generateKeyPair, id, keyIdOf, keyPairFromSeed, publicFromHex, requestString, responseString, sha256hex, signB64, token, verifyB64, type KeyPair } from "./crypto.ts";
import { FlowStore, type FlowRecord } from "./flows.ts";
import { Notifier, type FetchLike, type Urgency } from "./notify.ts";
import type { Moatctl } from "./moatctl.ts";
import type { OwnerAuthorization, SignResult } from "./signer.ts";

export type Role = "owner" | "viewer" | "launcher" | "agent";
export interface Principal { id: string; name: string; role: Role }
export interface Proposal { id: string; message: string; author: string; status: string; base_revision: number | null; rollback_of: number | null; created_at: string; source: string; diff: Record<string, unknown>; simulation: Record<string, unknown> | null; broadening: boolean; authorization_subject: string; authorization_digest: string }

/** The signer interface; in production a client for the separate `moat-signer` service. */
export interface SignerLike {
  keyId: string;
  publicHex: string;
  sign(req: { subject: string; source: string; revision: number; rollbackOf?: number | null; platforms: ("linux" | "macos" | "dns")[]; ownerAuthorization?: OwnerAuthorization | null; ownerSessionAttested?: boolean; issuedAt: Date }): Promise<SignResult>;
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
    const latest = this.db.prepare("SELECT s.revision, s.signed FROM snapshots s WHERE s.platform = ? ORDER BY s.revision DESC LIMIT 1").get(platformAdapter(d.platform)) as { revision: number; signed: string } | undefined;
    let snapshot: unknown = null;
    if (latest && (b.last_applied ?? 0) < latest.revision) {
      snapshot = JSON.parse(latest.signed);
      this.recordRevisionState(d.id, latest.revision, "distributed", null);
    }
    const actions = this.db.prepare("SELECT id, kind, args FROM device_actions WHERE device_id = ? AND done_at IS NULL ORDER BY created_at").all(d.id) as { id: string; kind: string; args: string }[];
    for (const a of actions) this.db.prepare("UPDATE device_actions SET delivered_at = COALESCE(delivered_at, ?) WHERE id = ?").run(at, a.id);
    return { snapshot, actions: actions.map((a) => ({ id: a.id, kind: a.kind, args: JSON.parse(a.args) })), acked_seq: ingest.maxSeq, gaps: ingest.gaps };
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
          const a = (e.attempt ?? {}) as { app?: { family?: string; executable?: string }; remote_ip?: string; remote_port?: number; transport?: string; hostname?: { name?: string }; session?: { id?: string; verified?: boolean }; process?: { pid?: number; start_generation?: number; boot_id?: string } };
          const dec = (e.decision ?? {}) as { verdict?: "allow" | "deny"; permitted_by_observation?: boolean; rule?: string; profile?: string; policy_revision?: number };
          const dest = a.hostname?.name ?? a.remote_ip ?? "unknown";
          const pi = a.process ? `${d.id}/${a.process.boot_id ?? ""}/${a.process.pid}@${a.process.start_generation}` : null;
          flowRecs.push({ attempt: e.attempt ? JSON.stringify(e.attempt) : null, seq: r.seq, at: r.at, kind: "flow", app: a.app?.family ?? a.app?.executable ?? null, session_id: a.session?.verified ? a.session.id ?? null : null, process_instance: pi, destination: dest, port: a.remote_port ?? null, transport: a.transport ?? null, verdict: dec.verdict ?? null, observed: !!dec.permitted_by_observation, rule: dec.rule ?? (dec.profile ? `default:${dec.profile}` : null), policy_revision: dec.policy_revision ?? null, measurement_source: String(e.measurement_source ?? "endpoint flow decision") });
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
          flowRecs.push({ seq: r.seq, at: r.at, kind: "coverage" });
          break;
        }
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
  acknowledge(actor: Principal, iid: string) {
    this.require(actor, "owner");
    const r = this.db.prepare("UPDATE incidents SET state = 'acknowledged', acknowledged_at = ?, acknowledged_occurrences = occurrences WHERE id = ? AND state = 'open'").run(this.iso(), iid);
    if (r.changes) this.db.prepare("INSERT INTO incident_log (incident_id, type, at, actor) VALUES (?, 'acknowledged', ?, ?)").run(iid, this.iso(), actor.id);
    return this.incident(iid);
  }
  resolve(actor: Principal, iid: string) {
    this.require(actor, "owner");
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
    if (!v.ok) throw new HttpError(422, `policy invalid: ${v.errors.join("; ")}`);
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
    return this.db.prepare("SELECT * FROM grants WHERE revoked_at IS NULL AND expires_at > ? ORDER BY created_at").all(this.iso()) as Record<string, unknown>[];
  }

  private platformsNeeded(): ("linux" | "macos" | "dns")[] {
    const set = new Set<"linux" | "macos" | "dns">(["linux", "macos"]);
    for (const r of this.db.prepare("SELECT DISTINCT platform FROM devices WHERE revoked_at IS NULL").all() as { platform: string }[]) set.add(platformAdapter(r.platform));
    set.delete("dns");
    return [...set];
  }

  /** Build source + grant overlay, have the signer authorize and sign it, store the revision. */
  private async publish(actor: Principal, base: string, subject: string, opts: { proposalId?: string; rollbackOf?: number | null; ownerAuthorization?: OwnerAuthorization | null; ownerSessionAttested?: boolean }) {
    const grants = this.activeGrants();
    const effective = base + grants.map(grantToml).join("");
    const revision = (this.currentRevision()?.revision ?? 0) + 1;
    const norm = await this.moatctl.run(["normalize", "@p.toml"], { "p.toml": base });
    const profiles = norm.code === 0 ? ((JSON.parse(norm.stdout) as { profiles: { id: string }[] }).profiles ?? []).map((p) => p.id) : [];
    const res = await this.signer.sign({ subject, source: effective, revision, rollbackOf: opts.rollbackOf ?? null, platforms: this.platformsNeeded(), ownerAuthorization: opts.ownerAuthorization ?? null, ownerSessionAttested: opts.ownerSessionAttested ?? false, issuedAt: this.now() });
    tx(this.db, () => {
      this.db.prepare("INSERT INTO policy_revisions (revision, proposal_id, source, source_digest, effective_source, rollback_of, grants, profiles, approved_by, owner_key_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(revision, opts.proposalId ?? null, base, sha256hex(base), effective, opts.rollbackOf ?? null, JSON.stringify(grants.map((g) => g.id)), JSON.stringify(profiles), actor.id, opts.ownerAuthorization?.key_id ?? null, this.iso());
      for (const s of res.snapshots) this.db.prepare("INSERT INTO snapshots (revision, platform, signed, report) VALUES (?, ?, ?, ?)").run(revision, s.platform, JSON.stringify(s.signed), JSON.stringify(s.report));
      for (const d of this.db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL").all() as { id: string }[]) this.recordRevisionState(d.id, revision, "approved", null);
      for (const g of grants) this.db.prepare("UPDATE grants SET revision = COALESCE(revision, ?) WHERE id = ?").run(revision, String(g.id));
    });
    audit(this.db, this.now(), actor.id, "policy.publish", String(revision), { subject, authorized_by: res.authorizedBy, broadening: res.broadening, grants: grants.length });
    return { revision, authorized_by: res.authorizedBy, broadening: res.broadening, platforms: res.snapshots.map((s) => ({ platform: s.platform, report: s.report })) };
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
    this.db.prepare("UPDATE policy_proposals SET status = 'approved', decided_at = ?, decided_by = ? WHERE id = ?").run(this.iso(), actor.id, pid);
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
    const revs = this.db.prepare("SELECT revision, proposal_id, source_digest, rollback_of, grants, approved_by, owner_key_id, created_at FROM policy_revisions ORDER BY revision DESC LIMIT 50").all() as { revision: number; proposal_id: string | null; source_digest: string; rollback_of: number | null; grants: string; approved_by: string; owner_key_id: string | null; created_at: string }[];
    return revs.map((r) => ({
      ...r,
      grants: JSON.parse(String(r.grants)),
      devices: this.db.prepare("SELECT device_id, state, at, detail FROM device_revisions WHERE revision = ? ORDER BY device_id, at").all(Number(r.revision)),
      platforms: this.db.prepare("SELECT platform, report FROM snapshots WHERE revision = ?").all(Number(r.revision)).map((s) => ({ platform: (s as { platform: string }).platform, report: JSON.parse((s as { report: string }).report) })),
    }));
  }

  // ------------------------------------------------------------------ temporary grants
  async createGrant(actor: Principal, b: { device_id?: unknown; session_id?: unknown; profile?: unknown; process_instance?: unknown; app_executable?: unknown; destination?: unknown; transport?: unknown; port?: unknown; ttl_seconds?: unknown; reason?: unknown; incident_id?: unknown; kind?: string }) {
    this.require(actor, "owner");
    const dest = String(b.destination ?? "");
    const isAddr = isIP(dest) !== 0;
    if (!isAddr && !/^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(dest)) throw new HttpError(400, "destination must be one IP address or one hostname");
    const transport = b.transport === "udp" ? "udp" : "tcp";
    const port = Number(b.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(400, "port must be 1-65535");
    const ttl = Math.min(ALLOW_ONCE_MAX_SECONDS, Math.max(60, Number(b.ttl_seconds ?? ALLOW_ONCE_DEFAULT_SECONDS)));
    const session = typeof b.session_id === "string" && b.session_id ? b.session_id : null;
    const exe = typeof b.app_executable === "string" && b.app_executable.startsWith("/") ? b.app_executable : null;
    if (!session && !exe) throw new HttpError(400, "a grant must be scoped to a session or an application");
    if (session && !/^[a-z0-9-]{1,64}$/.test(session)) throw new HttpError(400, "invalid session id");
    const gid = id("grant").replace("_", "-");
    const expires = new Date(this.now().getTime() + ttl * 1000).toISOString();
    const auditId = audit(this.db, this.now(), actor.id, "grant.create", gid, { session, exe, dest, transport, port, ttl, incident: b.incident_id ?? null, reason: b.reason ?? null });
    this.db.prepare("INSERT INTO grants (id, kind, device_id, session_id, profile, process_instance, destination, transport, port, expires_at, reason, incident_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(gid, b.kind ?? "temporary", typeof b.device_id === "string" ? b.device_id : null, session, typeof b.profile === "string" ? b.profile : null, typeof b.process_instance === "string" ? b.process_instance : exe, dest, transport, port, expires, `${String(b.reason ?? "").slice(0, 200)}|audit:${auditId}`, typeof b.incident_id === "string" ? b.incident_id : null, actor.id, this.iso());
    const cur = this.currentRevision();
    if (!cur) throw new HttpError(409, "no policy revision exists yet");
    try {
      const pub = await this.publish(actor, cur.source, gid, { ownerSessionAttested: actor.role === "owner" });
      return { grant_id: gid, expires_at: expires, ...pub, delivery: "queued for devices; see revision states for received/applied" };
    } catch (e) {
      this.db.prepare("UPDATE grants SET revoked_at = ? WHERE id = ?").run(this.iso(), gid);
      const err = e as { status?: number; message?: string };
      throw new HttpError(err.status ?? 500, err.message ?? String(e));
    }
  }

  async revokeGrant(actor: Principal, gid: string) {
    this.require(actor, "owner");
    const r = this.db.prepare("UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(this.iso(), gid);
    if (!r.changes) throw new HttpError(404, "no such active grant");
    audit(this.db, this.now(), actor.id, "grant.revoke", gid, null);
    const cur = this.currentRevision()!;
    return this.publish(actor, cur.source, `revoke:${gid}`, {});
  }

  grants(): (Record<string, unknown> & { id: string; state: string })[] {
    return (this.db.prepare("SELECT * FROM grants ORDER BY created_at DESC LIMIT 100").all() as (Record<string, unknown> & { id: string })[]).map((g) => ({ ...g, state: g.revoked_at ? "revoked" : String(g.expires_at) <= this.iso() ? "expired" : "active" }));
  }

  /**
   * "Allow once for this session": bound to the incident, the policy revision the owner saw, the incident's session
   * and process instance, and the authenticated owner. Rejected when stale (newer policy, ended session, a different
   * process instance than the one the notification described, or an incident that has changed since).
   */
  async allowOnce(actor: Principal, b: { incident_id?: unknown; incident_revision?: unknown; policy_revision?: unknown; ttl_seconds?: unknown }) {
    this.require(actor, "owner");
    const inc = this.db.prepare("SELECT * FROM incidents WHERE id = ?").get(String(b.incident_id ?? "")) as unknown as IncidentRow | undefined;
    if (!inc) throw new HttpError(404, "no such incident");
    if (inc.kind !== "blocked_connection" || !inc.session_id) throw new HttpError(422, "allow once applies to a blocked connection from a verified protected session");
    if (Number(b.incident_revision) !== inc.revision) throw new HttpError(409, "stale: the incident changed since this action was offered; review it again");
    const cur = this.currentRevision();
    if (!cur || Number(b.policy_revision) !== cur.revision) throw new HttpError(409, `stale: policy is now revision ${cur?.revision}; review again`);
    const sess = this.db.prepare("SELECT * FROM sessions WHERE device_id = ? AND id = ?").get(inc.device_id, inc.session_id) as { state: string; root_pid: number; root_start: number } | undefined;
    if (!sess || sess.state !== "running") throw new HttpError(409, "stale: that session is no longer running");
    if (!inc.port || inc.destination === "rule-scoped") throw new HttpError(422, "this platform did not record the destination; create a reviewed policy change instead");
    const ip = inc.destination;
    return this.createGrant(actor, { kind: "allow_once", device_id: inc.device_id, session_id: inc.session_id, process_instance: inc.process_instance, destination: ip, transport: inc.transport ?? "tcp", port: inc.port, ttl_seconds: b.ttl_seconds ?? ALLOW_ONCE_DEFAULT_SECONDS, reason: `allow once for incident ${inc.id}`, incident_id: inc.id });
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
      revision: this.currentRevision()?.revision ?? null,
      devices: devices.map((d) => ({ id: d.id, name: d.name, platform: d.platform, coverage: d.coverage, effective_coverage: d.effective_coverage, stale: d.stale, last_seen_at: d.last_seen_at, last_revision: d.last_revision })),
      open_incidents: open.n,
      active_grants: this.activeGrants().length,
      retention: this.flows.retention(),
      notifications: this.notifier.status(),
    };
  }
}

/** Render one grant as an override rule (owner_action provenance, audit ref, expiry). */
export function grantToml(g: Record<string, unknown>): string {
  const dest = String(g.destination);
  const destToml = isIP(dest) ? `{ cidrs = [${JSON.stringify(dest + (isIP(dest) === 6 ? "/128" : "/32"))}] }` : `{ hosts = [${JSON.stringify(dest)}] }`;
  const selector = g.session_id
    ? `{ session = { ${g.profile ? `profiles = [${JSON.stringify(g.profile)}], ` : ""}session_ids = [${JSON.stringify(g.session_id)}] } }`
    : `{ apps = [{ executable = ${JSON.stringify(g.process_instance)} }] }`;
  const auditRef = String(g.reason).split("|audit:")[1] ?? "unknown";
  return `
[[rules]]
id = ${JSON.stringify(String(g.id))}
description = ${JSON.stringify(`Temporary grant (${g.kind}) by ${g.created_by}`)}
action = "allow"
layer = "override"
selector = ${selector}
destinations = ${destToml}
transport = ${JSON.stringify(g.transport)}
ports = [${Number(g.port)}]
expires_at = ${JSON.stringify(g.expires_at)}
provenance = { kind = "owner_action", reference = ${JSON.stringify(`grant:${g.id}`)}, author = ${JSON.stringify(String(g.created_by))}, audit_ref = ${JSON.stringify(`audit:${auditRef}`)} }
`;
}
