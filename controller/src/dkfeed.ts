/**
 * Digital Kingdom evidence feed (W16): forwards significant Moat evidence into a Digital Kingdom server
 * (robzilla1738/Digital-Kingdom, `POST /ingest/events`, source-key authenticated). Optional; enforcement never depends
 * on it.
 *
 * Producer authority follows DK's contracts and server-side capabilities (packages/contracts/src/types.ts and
 * packages/detections/src/capabilities.ts @ e0452c8). Moat registers as one source of kind `agent_observer`. That
 * kind may report only `tool_invocation` plus sensor health, and only for the assets it is assigned (`device:<id>`
 * for each enrolled Moat endpoint). `producerRegistration()` emits exactly that document for the owner to register in
 * DK, and every event is checked against it before it leaves (`authorityProblem`). DK enforces it again on ingest.
 *
 * What each event may claim:
 *  - An endpoint's own block decision: `tool_invocation` / `blocked`, agent `{ phase: "decision", origin:
 *    "policy_enforcer" }`. It is the enforcer's report, never an independent observation.
 *  - Coverage loss / telemetry gap: `sensor_unavailable`.
 *  - An agent/harness self-reported intent: `tool_invocation` / `unknown`, agent `{ phase: "intent", origin:
 *    "runtime_self_report" }`. Agent intent never carries `blocked`, `denied` or `success`, so it cannot attest
 *    enforcement.
 *  - DNS-only evidence (`dns_blocked`) is not sent. A resolver block is not an endpoint flow decision, and
 *    `agent_observer` has no capability for it.
 * Payloads carry identifiers and labels only: no payloads, command lines, prompts, intent text or URL query strings.
 */
import type { DB } from "./db.ts";
import type { FetchLike } from "./notify.ts";

export interface DkEvent {
  source_event_id: string;
  occurred_at: string;
  asset_ids: string[];
  action: "tool_invocation" | "sensor_unavailable" | "sensor_restored";
  outcome: "blocked" | "allowed" | "observed" | "unknown" | "attempted";
  session_ref?: string;
  rule_ref?: string;
  severity?: "low" | "medium" | "high";
  coverage_note?: string;
  attributes?: Record<string, string | number | boolean>;
  agent?: { phase: "intent" | "decision"; origin: "policy_enforcer" | "runtime_self_report"; policy_revision?: string; tool?: string };
}

/** The DK source registration Moat needs (and may use) — nothing broader. */
export function producerRegistration(db: DB, sourceId = "moat") {
  const devices = (db.prepare("SELECT id FROM devices WHERE revoked_at IS NULL ORDER BY id").all() as { id: string }[]).map((d) => `device:${d.id}`);
  return {
    id: sourceId,
    kind: "agent_observer",
    asset_ids: devices,
    allowed_actions: ["tool_invocation", "sensor_unavailable", "sensor_restored"],
    independence_group: "moat-endpoints",
    note: "Moat endpoint decisions relayed by the Moat controller: a policy enforcer's reports, one independence group. Never side_effect_observed or decoy_used.",
  };
}

const ALLOWED = new Set(["tool_invocation", "sensor_unavailable", "sensor_restored"]);
const ENFORCEMENT = new Set(["blocked", "denied", "allowed", "success"]);

/** Why this event must not be sent under Moat's producer authority, or null. */
export function authorityProblem(e: DkEvent, assets: Set<string>): string | null {
  if (!ALLOWED.has(e.action)) return `action ${e.action} is outside the agent_observer capability`;
  const outside = e.asset_ids.filter((a) => !assets.has(a));
  if (outside.length) return `asset ${outside[0]} is not an enrolled Moat endpoint`;
  if (e.action === "tool_invocation") {
    if (!e.agent) return "a tool_invocation needs agent phase/origin context";
    if (ENFORCEMENT.has(e.outcome) && !(e.agent.phase === "decision" && e.agent.origin === "policy_enforcer")) return `only an endpoint's policy decision may report outcome ${e.outcome}`;
    if (e.agent.phase === "intent" && e.outcome !== "unknown") return "agent intent cannot carry an outcome";
  }
  return null;
}

interface IncidentRow { id: string; kind: string; device_id: string; session_id: string | null; app: string | null; destination: string; port: number | null; transport: string | null; rule: string | null; policy_revision: number | null; urgency: string; occurrences: number; first_at: string; last_at: string; revision: number }

export function toDkEvent(i: IncidentRow): DkEvent | null {
  const asset = `device:${i.device_id}`;
  if (i.kind === "blocked_connection") {
    return {
      source_event_id: `moat:${i.id}:r${i.revision}`,
      occurred_at: i.last_at,
      asset_ids: [asset],
      action: "tool_invocation",
      outcome: "blocked",
      session_ref: i.session_id ?? undefined,
      rule_ref: i.rule ?? undefined,
      severity: i.urgency === "high" ? "high" : i.urgency === "medium" ? "medium" : "low",
      attributes: { destination: i.destination, port: i.port ?? 0, transport: i.transport ?? "unknown", occurrences: i.occurrences, app: i.app ?? "unknown" },
      agent: { phase: "decision", origin: "policy_enforcer", policy_revision: i.policy_revision ? String(i.policy_revision) : undefined, tool: i.app ?? undefined },
      coverage_note: "Reported by the Moat endpoint that enforced the decision (policy enforcer), not an independent observer.",
    };
  }
  if (i.kind === "coverage_lost" || i.kind === "telemetry_gap" || i.kind === "recovery_required") {
    return { source_event_id: `moat:${i.id}:r${i.revision}`, occurred_at: i.last_at, asset_ids: [asset], action: "sensor_unavailable", outcome: "observed", severity: "high", coverage_note: i.kind === "telemetry_gap" ? "Moat event sequence gap" : i.kind === "recovery_required" ? "Moat endpoint needs owner recovery" : "Moat endpoint reported loss of enforcement" };
  }
  return null; // dns_blocked (DNS-only), policy_* and the rest are not DK producer evidence
}

interface SessionRow { rid: number; id: string; device_id: string; profile: string; started_at: string | null; intent: string | null }

/** A harness/agent self-reported task intent: context for investigation, never enforcement evidence. */
export function intentEvent(s: SessionRow): DkEvent {
  return {
    source_event_id: `moat:intent:${s.device_id}:${s.id}`,
    occurred_at: s.started_at ?? new Date(0).toISOString(),
    asset_ids: [`device:${s.device_id}`],
    action: "tool_invocation",
    outcome: "unknown",
    session_ref: s.id,
    attributes: { profile: s.profile, intent_declared: true },
    agent: { phase: "intent", origin: "runtime_self_report" },
    coverage_note: "Self-reported by the launching harness. It describes intent only and is not evidence of any decision or effect.",
  };
}

const MAX_BACKOFF_MS = 30 * 60_000;

export class DkFeed {
  db: DB;
  url: string;
  sourceKey: string;
  fetchImpl: FetchLike;
  now: () => Date;
  baseBackoffMs: number;
  constructor(db: DB, url: string, sourceKey: string, fetchImpl: FetchLike, now: () => Date = () => new Date(), baseBackoffMs = 30_000) {
    this.db = db;
    this.url = url.replace(/\/$/, "");
    this.sourceKey = sourceKey;
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.baseBackoffMs = baseBackoffMs;
    db.prepare("INSERT OR IGNORE INTO dk_feed_state (name, health, failures) VALUES ('dk', 'never_sent', 0)").run();
  }

  private cursor(name: string): number {
    return (this.db.prepare("SELECT last_seq FROM feed_cursor WHERE name = ?").get(name) as { last_seq: number } | undefined)?.last_seq ?? 0;
  }
  private setCursor(name: string, v: number) {
    this.db.prepare("INSERT INTO feed_cursor (name, last_seq) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET last_seq = excluded.last_seq").run(name, v);
  }

  health() {
    const s = this.db.prepare("SELECT * FROM dk_feed_state WHERE name = 'dk'").get() as Record<string, unknown>;
    return { ...s, cursor: this.cursor("dk"), intent_cursor: this.cursor("dk-intent"), backlog: (this.db.prepare("SELECT COUNT(*) AS n FROM incident_log WHERE seq > ? AND type IN ('raised','occurrence','reopened','recurred')").get(this.cursor("dk")) as { n: number }).n };
  }

  due(): boolean {
    const s = this.db.prepare("SELECT next_attempt_at FROM dk_feed_state WHERE name = 'dk'").get() as { next_attempt_at: string | null };
    return !s.next_attempt_at || Date.parse(s.next_attempt_at) <= this.now().getTime();
  }

  /**
   * Send evidence newer than the cursors, at least once. DK deduplicates by `source_event_id`, so a retry after a
   * lost reply re-sends the same ids and never creates new events. Cursors advance only after DK accepted the batch.
   * Events outside Moat's producer authority are dropped here (counted), never sent.
   */
  async push(limit = 200) {
    const at = this.now().toISOString();
    const assets = new Set(producerRegistration(this.db).asset_ids);
    const cur = this.cursor("dk");
    const icur = this.cursor("dk-intent");
    const rows = this.db.prepare("SELECT l.seq, i.* FROM incident_log l JOIN incidents i ON i.id = l.incident_id WHERE l.seq > ? AND l.type IN ('raised','occurrence','reopened','recurred') ORDER BY l.seq LIMIT ?").all(cur, limit) as unknown as (IncidentRow & { seq: number })[];
    const srows = this.db.prepare("SELECT rowid AS rid, id, device_id, profile, started_at, intent FROM sessions WHERE rowid > ? AND intent IS NOT NULL ORDER BY rowid LIMIT ?").all(icur, limit) as unknown as SessionRow[];
    const candidates = [...rows.map(toDkEvent), ...srows.map(intentEvent)].filter((e): e is DkEvent => !!e);
    const dropped: string[] = [];
    const events = candidates.filter((e) => {
      const p = authorityProblem(e, assets);
      if (p) dropped.push(`${e.source_event_id}: ${p}`);
      return !p;
    });
    if (!rows.length && !srows.length) return { sent: 0, dropped, cursor: cur };
    if (events.length) {
      let status = 0;
      let err: string | null = null;
      try {
        status = (await this.fetchImpl(`${this.url}/ingest/events`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.sourceKey}` }, body: JSON.stringify({ events }), signal: AbortSignal.timeout(15_000) })).status;
      } catch (e) {
        err = `unreachable: ${String((e as Error).message ?? e)}`;
      }
      if (status !== 200 && status !== 202) {
        const st = this.db.prepare("SELECT failures FROM dk_feed_state WHERE name = 'dk'").get() as { failures: number };
        const failures = st.failures + 1;
        // 401/403/422: the credential or the registered capability refused it; retrying the same batch will not help
        const refused = status === 401 || status === 403 || status === 422;
        const health = err ? "unreachable" : refused ? "refused" : "error";
        const msg = err ?? `digital kingdom ingest returned HTTP ${status}`;
        this.db.prepare("UPDATE dk_feed_state SET health = ?, last_attempt_at = ?, last_error = ?, failures = ?, next_attempt_at = ?, refused = refused + ? WHERE name = 'dk'")
          .run(health, at, msg, failures, new Date(this.now().getTime() + Math.min(MAX_BACKOFF_MS, this.baseBackoffMs * 2 ** Math.min(failures, 10))).toISOString(), refused ? 1 : 0);
        throw new Error(msg);
      }
    }
    if (rows.length) this.setCursor("dk", rows[rows.length - 1]!.seq);
    if (srows.length) this.setCursor("dk-intent", srows[srows.length - 1]!.rid);
    this.db.prepare("UPDATE dk_feed_state SET health = 'ok', last_ok_at = ?, last_attempt_at = ?, last_error = NULL, failures = 0, next_attempt_at = NULL WHERE name = 'dk'").run(at, at);
    return { sent: events.length, dropped, cursor: rows.length ? rows[rows.length - 1]!.seq : cur };
  }
}
