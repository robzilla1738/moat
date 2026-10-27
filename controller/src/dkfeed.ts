/**
 * Digital Kingdom evidence feed: forwards significant Moat incidents into a Digital Kingdom server
 * (robzilla1738/Digital-Kingdom, `POST /ingest/events`, source-key authenticated).
 *
 * Mapping follows DK's contracts (packages/contracts/src/types.ts @ e0452c8): a block decided by the endpoint is a
 * `tool_invocation` with outcome `blocked` and agent context { phase: "decision", origin: "policy_enforcer" } — a
 * policy enforcer's report, never an independent observation. Loss of coverage maps to `sensor_unavailable`.
 * Register the Moat source in DK as kind `agent_observer` so its capabilities are limited to those categories.
 * Payloads carry identifiers and labels only: no payloads, command lines, prompts or URL query strings.
 */
import type { DB } from "./db.ts";
import type { FetchLike } from "./notify.ts";

export interface DkEvent {
  source_event_id: string;
  occurred_at: string;
  asset_ids: string[];
  action: "tool_invocation" | "sensor_unavailable" | "sensor_restored";
  outcome: "blocked" | "allowed" | "observed" | "unknown";
  session_ref?: string;
  rule_ref?: string;
  severity?: "low" | "medium" | "high";
  coverage_note?: string;
  attributes?: Record<string, string | number | boolean>;
  agent?: { phase: "decision"; origin: "policy_enforcer"; policy_revision?: string; tool?: string };
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
  if (i.kind === "coverage_lost" || i.kind === "telemetry_gap") {
    return { source_event_id: `moat:${i.id}:r${i.revision}`, occurred_at: i.last_at, asset_ids: [asset], action: "sensor_unavailable", outcome: "observed", severity: "high", coverage_note: i.kind === "telemetry_gap" ? "Moat event sequence gap" : "Moat endpoint reported loss of enforcement" };
  }
  return null;
}

export class DkFeed {
  db: DB;
  url: string;
  sourceKey: string;
  fetchImpl: FetchLike;
  constructor(db: DB, url: string, sourceKey: string, fetchImpl: FetchLike) {
    this.db = db;
    this.url = url.replace(/\/$/, "");
    this.sourceKey = sourceKey;
    this.fetchImpl = fetchImpl;
  }

  /** Send incident revisions newer than the cursor. Durable cursor; DK deduplicates by source_event_id. */
  async push(limit = 200) {
    const cur = (this.db.prepare("SELECT last_seq FROM feed_cursor WHERE name = 'dk'").get() as { last_seq: number } | undefined)?.last_seq ?? 0;
    const rows = this.db.prepare("SELECT l.seq, i.* FROM incident_log l JOIN incidents i ON i.id = l.incident_id WHERE l.seq > ? AND l.type IN ('raised','occurrence','reopened') ORDER BY l.seq LIMIT ?").all(cur, limit) as unknown as (IncidentRow & { seq: number })[];
    const events = rows.map(toDkEvent).filter((e): e is DkEvent => !!e);
    if (!rows.length) return { sent: 0, cursor: cur };
    if (events.length) {
      const r = await this.fetchImpl(`${this.url}/ingest/events`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${this.sourceKey}` }, body: JSON.stringify({ events }) });
      if (r.status !== 202 && r.status !== 200) throw new Error(`digital kingdom ingest returned HTTP ${r.status}`);
    }
    const last = rows[rows.length - 1]!.seq;
    this.db.prepare("INSERT INTO feed_cursor (name, last_seq) VALUES ('dk', ?) ON CONFLICT (name) DO UPDATE SET last_seq = excluded.last_seq").run(last);
    return { sent: events.length, cursor: last };
  }
}
