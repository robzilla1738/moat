/**
 * Flow store: a separate SQLite database for high-volume connection records and counters.
 *
 *  - batched: a device upload is written in one transaction;
 *  - rollups: hourly counters per (device, app/session, destination, verdict, rule) updated in the same transaction;
 *  - retention: raw records 30 days, rollups 90 days by default, plus a disk quota that trims the oldest raw records
 *    first; the current retention boundary is queryable so the UI can show where history stops;
 *  - bounded queries only (limit ≤ 1000).
 *
 * This is deliberately separate from the evidence pipeline (the roadmap's warning about Digital Kingdom's synchronous
 * SQLite and bounded evaluation windows). Interesting events are forwarded as incidents/evidence references instead.
 */
import { statSync } from "node:fs";
import { openDb, tx, type DB } from "./db.ts";

export const FLOW_MIGRATIONS = [
  `CREATE TABLE flows (id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, seq INTEGER NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, app TEXT, session_id TEXT, process_instance TEXT, destination TEXT, port INTEGER, transport TEXT, verdict TEXT, observed INTEGER NOT NULL DEFAULT 0, rule TEXT, policy_revision INTEGER, packets INTEGER, bytes_out INTEGER, bytes_in INTEGER, counter_scope TEXT, measurement_source TEXT, attempt TEXT, UNIQUE (device_id, seq));
   CREATE INDEX flows_at ON flows (at);
   CREATE INDEX flows_device_at ON flows (device_id, at);
   CREATE TABLE rollups (hour TEXT NOT NULL, device_id TEXT NOT NULL, app TEXT NOT NULL, destination TEXT NOT NULL, verdict TEXT NOT NULL, rule TEXT NOT NULL, flows INTEGER NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (hour, device_id, app, destination, verdict, rule));
   CREATE TABLE device_seq (device_id TEXT PRIMARY KEY, max_seq INTEGER NOT NULL, gaps TEXT NOT NULL DEFAULT '[]');
   CREATE TABLE retention (id INTEGER PRIMARY KEY CHECK (id = 1), raw_before TEXT, rollup_before TEXT, trimmed_for_quota INTEGER NOT NULL DEFAULT 0, ran_at TEXT);
   INSERT INTO retention (id) VALUES (1);`,
  // 2 (W12): exact executable and signer identity per flow (an app family name alone is never identity), and a
  // short typed detail for non-flow evidence (coverage level, recovery phase) so "What changed?" can compare intervals.
  `ALTER TABLE flows ADD COLUMN exe TEXT;
   ALTER TABLE flows ADD COLUMN signer TEXT;
   ALTER TABLE flows ADD COLUMN detail TEXT;
   CREATE INDEX flows_exe_at ON flows (exe, at);`,
  // 3 (W13): at-least-once delivery. `contiguous` is the acknowledgement high-water: every seq at or below it was
  // stored or explicitly declared lost. Out-of-order records above it are stored but not acknowledged.
  `ALTER TABLE device_seq ADD COLUMN contiguous INTEGER NOT NULL DEFAULT 0;
   UPDATE device_seq SET contiguous = max_seq;`,
];

export interface FlowRecord {
  seq: number;
  at: string;
  kind: string; // flow | rule_counter
  app?: string | null;
  session_id?: string | null;
  process_instance?: string | null;
  destination?: string | null;
  port?: number | null;
  transport?: string | null;
  verdict?: "allow" | "deny" | null;
  observed?: boolean;
  rule?: string | null;
  policy_revision?: number | null;
  packets?: number | null;
  bytes_out?: number | null;
  bytes_in?: number | null;
  counter_scope?: string | null;
  measurement_source?: string | null;
  /** The endpoint's flow attempt (moat-core FlowAttempt JSON), kept for replay in policy simulation. */
  attempt?: string | null;
  /** Executable path as the endpoint observed it (null: identity unknown). */
  exe?: string | null;
  /** Code-signing identity (team/signing id) when the platform reports one. */
  signer?: string | null;
  /** Typed detail for non-flow evidence (e.g. coverage level). */
  detail?: string | null;
}

export interface RetentionPolicy { rawDays: number; rollupDays: number; maxBytes: number }
export const DEFAULT_RETENTION: RetentionPolicy = { rawDays: 30, rollupDays: 90, maxBytes: 2 * 1024 * 1024 * 1024 };

export class FlowStore {
  db: DB;
  path: string;
  constructor(path: string) {
    this.path = path;
    this.db = openDb(path, FLOW_MIGRATIONS);
  }

  /**
   * Insert a batch in one transaction. Delivery is at-least-once: duplicates (same device + seq) are ignored, records
   * may arrive out of order, and the returned `acked` is the contiguous high-water (every seq ≤ acked is stored or was
   * declared lost by the endpoint). A hole above it is *pending*, not a gap: the endpoint keeps unacknowledged records
   * and resends them. A hole becomes a gap only when the endpoint says it no longer has those records
   * (`lostRanges`: its own gap events, or everything below its spool's lowest retained seq).
   */
  insertBatch(deviceId: string, records: FlowRecord[], lostRanges: [number, number][] = []): { inserted: number; duplicates: number; gaps: [number, number][]; acked: number; pending: [number, number][] } {
    return tx(this.db, () => {
      const ins = this.db.prepare(
        "INSERT OR IGNORE INTO flows (device_id, seq, at, kind, app, session_id, process_instance, destination, port, transport, verdict, observed, rule, policy_revision, packets, bytes_out, bytes_in, counter_scope, measurement_source, attempt, exe, signer, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      const roll = this.db.prepare(
        "INSERT INTO rollups (hour, device_id, app, destination, verdict, rule, flows, packets, bytes) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) ON CONFLICT (hour, device_id, app, destination, verdict, rule) DO UPDATE SET flows = flows + 1, packets = packets + excluded.packets, bytes = bytes + excluded.bytes",
      );
      let inserted = 0;
      const prev = (this.db.prepare("SELECT max_seq, gaps, contiguous FROM device_seq WHERE device_id = ?").get(deviceId) as { max_seq: number; gaps: string; contiguous: number } | undefined) ?? { max_seq: 0, gaps: "[]", contiguous: 0 };
      let max = prev.max_seq;
      for (const r of [...records].sort((a, b) => a.seq - b.seq)) {
        if (r.seq > max) max = r.seq;
        const res = ins.run(deviceId, r.seq, r.at, r.kind, r.app ?? null, r.session_id ?? null, r.process_instance ?? null, r.destination ?? null, r.port ?? null, r.transport ?? null, r.verdict ?? null, r.observed ? 1 : 0, r.rule ?? null, r.policy_revision ?? null, r.packets ?? null, r.bytes_out ?? null, r.bytes_in ?? null, r.counter_scope ?? null, r.measurement_source ?? null, r.attempt ?? null, r.exe ?? null, r.signer ?? null, r.detail ?? null);
        if (res.changes) {
          inserted++;
          roll.run(r.at.slice(0, 13) + ":00:00Z", deviceId, r.app ?? r.session_id ?? "", r.destination ?? "", r.verdict ?? (r.observed ? "observed" : ""), r.rule ?? "", r.packets ?? 0, (r.bytes_out ?? 0) + (r.bytes_in ?? 0));
        }
      }
      // Lost ranges the endpoint declared: recorded once each (only the part not already stored or recorded).
      const known = JSON.parse(prev.gaps) as [number, number][];
      const newGaps: [number, number][] = [];
      const has = this.db.prepare("SELECT 1 FROM flows WHERE device_id = ? AND seq = ?");
      for (const [a, b] of lostRanges) {
        if (!(a >= 1 && b >= a)) continue;
        let runStart: number | null = null;
        for (let q = a; q <= Math.min(b, a + 100_000); q++) {
          const covered = known.some(([x, y]) => q >= x && q <= y) || newGaps.some(([x, y]) => q >= x && q <= y) || !!has.get(deviceId, q);
          if (!covered && runStart === null) runStart = q;
          if (covered && runStart !== null) (newGaps.push([runStart, q - 1]), (runStart = null));
        }
        if (runStart !== null) newGaps.push([runStart, Math.min(b, a + 100_000)]);
        if (b > max) max = b;
      }
      const allGaps = [...known, ...newGaps].slice(-200);
      // Advance the acknowledgement high-water over stored records and declared-lost ranges only.
      let contiguous = prev.contiguous;
      const next = this.db.prepare("SELECT seq FROM flows WHERE device_id = ? AND seq > ? ORDER BY seq LIMIT 1000");
      for (;;) {
        const before = contiguous;
        const gap = allGaps.find(([x, y]) => x <= contiguous + 1 && y > contiguous);
        if (gap) contiguous = gap[1];
        for (const row of next.all(deviceId, contiguous) as { seq: number }[]) {
          if (row.seq === contiguous + 1) contiguous = row.seq;
          else break;
        }
        if (contiguous === before) break;
      }
      const pending: [number, number][] = [];
      if (max > contiguous) {
        let q = contiguous + 1;
        for (const row of next.all(deviceId, contiguous) as { seq: number }[]) {
          if (row.seq > q) pending.push([q, row.seq - 1]);
          q = row.seq + 1;
          if (pending.length > 50) break;
        }
      }
      this.db.prepare("INSERT INTO device_seq (device_id, max_seq, gaps, contiguous) VALUES (?, ?, ?, ?) ON CONFLICT (device_id) DO UPDATE SET max_seq = excluded.max_seq, gaps = excluded.gaps, contiguous = excluded.contiguous").run(deviceId, max, JSON.stringify(allGaps), contiguous);
      return { inserted, duplicates: records.length - inserted, gaps: newGaps, acked: contiguous, pending };
    });
  }

  /** Acknowledgement state for a device (W13 diagnostics). */
  ackState(deviceId: string): { acked: number; max: number } {
    const r = this.db.prepare("SELECT contiguous, max_seq FROM device_seq WHERE device_id = ?").get(deviceId) as { contiguous: number; max_seq: number } | undefined;
    return { acked: r?.contiguous ?? 0, max: r?.max_seq ?? 0 };
  }

  recent(opts: { deviceId?: string; verdict?: string; limit?: number; before?: string } = {}) {
    const limit = Math.min(1000, Math.max(1, opts.limit ?? 100));
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (opts.deviceId) (where.push("device_id = ?"), args.push(opts.deviceId));
    if (opts.verdict) (where.push("verdict = ?"), args.push(opts.verdict));
    if (opts.before) (where.push("at < ?"), args.push(opts.before));
    return this.db.prepare(`SELECT * FROM flows ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY at DESC, id DESC LIMIT ?`).all(...args, limit);
  }

  rollups(opts: { sinceHour: string; deviceId?: string; limit?: number }) {
    const limit = Math.min(1000, opts.limit ?? 200);
    return opts.deviceId
      ? this.db.prepare("SELECT * FROM rollups WHERE hour >= ? AND device_id = ? ORDER BY hour DESC, flows DESC LIMIT ?").all(opts.sinceHour, opts.deviceId, limit)
      : this.db.prepare("SELECT * FROM rollups WHERE hour >= ? ORDER BY hour DESC, flows DESC LIMIT ?").all(opts.sinceHour, limit);
  }

  /** Recent replayable flow attempts as JSON lines (for moatctl simulate). */
  observationsJsonl(limit = 5000): string {
    const rows = this.db.prepare("SELECT attempt FROM flows WHERE attempt IS NOT NULL ORDER BY at DESC LIMIT ?").all(Math.min(limit, 20000)) as { attempt: string }[];
    return rows.map((r) => r.attempt).join("\n");
  }

  gaps(deviceId: string): [number, number][] {
    const r = this.db.prepare("SELECT gaps FROM device_seq WHERE device_id = ?").get(deviceId) as { gaps: string } | undefined;
    return r ? (JSON.parse(r.gaps) as [number, number][]) : [];
  }

  sizeBytes(): number {
    if (this.path === ":memory:") {
      const r = this.db.prepare("SELECT page_count * page_size AS b FROM pragma_page_count(), pragma_page_size()").get() as { b: number };
      return r.b;
    }
    let total = 0;
    for (const suffix of ["", "-wal"]) {
      try {
        total += statSync(this.path + suffix).size;
      } catch {
        /* absent */
      }
    }
    return total;
  }

  /** Apply retention. Returns the boundaries now in force. */
  retain(now: Date, policy: RetentionPolicy = DEFAULT_RETENTION) {
    const rawBefore = new Date(now.getTime() - policy.rawDays * 86400_000).toISOString();
    const rollBefore = new Date(now.getTime() - policy.rollupDays * 86400_000).toISOString();
    let trimmed = 0;
    tx(this.db, () => {
      this.db.prepare("DELETE FROM flows WHERE at < ?").run(rawBefore);
      this.db.prepare("DELETE FROM rollups WHERE hour < ?").run(rollBefore);
    });
    // Disk quota: drop the oldest raw records in chunks until under quota (rollups are kept).
    let boundary = rawBefore;
    for (let i = 0; i < 50 && this.sizeBytes() > policy.maxBytes; i++) {
      const cut = this.db.prepare("SELECT at FROM flows ORDER BY at LIMIT 1 OFFSET (SELECT MAX(1, COUNT(*) / 10) FROM flows)").get() as { at: string } | undefined;
      if (!cut) break;
      const r = this.db.prepare("DELETE FROM flows WHERE at < ?").run(cut.at);
      trimmed += Number(r.changes);
      boundary = cut.at;
      this.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
      if (this.path !== ":memory:") this.db.exec("VACUUM");
    }
    this.db.prepare("UPDATE retention SET raw_before = ?, rollup_before = ?, trimmed_for_quota = trimmed_for_quota + ?, ran_at = ? WHERE id = 1").run(boundary, rollBefore, trimmed, now.toISOString());
    return this.retention();
  }

  retention() {
    return this.db.prepare("SELECT raw_before, rollup_before, trimmed_for_quota, ran_at FROM retention WHERE id = 1").get() as { raw_before: string | null; rollup_before: string | null; trimmed_for_quota: number; ran_at: string | null };
  }
}
