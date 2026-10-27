/**
 * Control database (devices, policy, grants, audit, attention, notifications). High-volume flow records live in a
 * separate database (flows.ts) so logging load never contends with policy and enrollment.
 *
 * Provenance: the migration-list pattern and the append-only audit/log triggers follow Digital Kingdom
 * (robzilla1738/Digital-Kingdom@e0452c8, apps/server/src/db.ts and attention.ts, Apache-2.0).
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type DB = DatabaseSync;

export const CONTROL_MIGRATIONS: string[] = [
  `CREATE TABLE tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('owner','viewer','launcher','agent')), token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT);
   CREATE TABLE owner_keys (key_id TEXT PRIMARY KEY, public_hex TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
   CREATE TABLE enrollment_codes (code_hash TEXT PRIMARY KEY, created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, device_id TEXT, device_groups TEXT NOT NULL DEFAULT '[]');
   CREATE TABLE devices (id TEXT PRIMARY KEY, name TEXT NOT NULL, platform TEXT NOT NULL, public_hex TEXT NOT NULL, key_id TEXT NOT NULL UNIQUE, enrolled_at TEXT NOT NULL, revoked_at TEXT, last_seen_at TEXT, capabilities TEXT, last_revision INTEGER, coverage TEXT, status TEXT);
   CREATE TABLE nonces (key_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at TEXT NOT NULL, PRIMARY KEY (key_id, nonce));
   CREATE TABLE policy_proposals (id TEXT PRIMARY KEY, source TEXT NOT NULL, source_digest TEXT NOT NULL, message TEXT NOT NULL, author TEXT NOT NULL, base_revision INTEGER, diff TEXT NOT NULL, broadening INTEGER NOT NULL, simulation TEXT, rollback_of INTEGER, status TEXT NOT NULL CHECK (status IN ('open','approved','rejected','superseded')), created_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT);
   CREATE TABLE policy_revisions (revision INTEGER PRIMARY KEY, proposal_id TEXT, source TEXT NOT NULL, source_digest TEXT NOT NULL, effective_source TEXT NOT NULL, rollback_of INTEGER, grants TEXT NOT NULL DEFAULT '[]', profiles TEXT NOT NULL DEFAULT '[]', approved_by TEXT NOT NULL, owner_key_id TEXT, created_at TEXT NOT NULL);
   CREATE TABLE snapshots (revision INTEGER NOT NULL, platform TEXT NOT NULL, signed TEXT NOT NULL, report TEXT NOT NULL, PRIMARY KEY (revision, platform));
   CREATE TABLE device_revisions (device_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('approved','distributed','received','applied','verified','rejected')), at TEXT NOT NULL, detail TEXT, PRIMARY KEY (device_id, revision, state));
   CREATE TABLE grants (id TEXT PRIMARY KEY, kind TEXT NOT NULL, device_id TEXT, session_id TEXT, profile TEXT, process_instance TEXT, destination TEXT NOT NULL, transport TEXT NOT NULL, port INTEGER, expires_at TEXT NOT NULL, reason TEXT NOT NULL, incident_id TEXT, created_by TEXT NOT NULL, owner_key_id TEXT, created_at TEXT NOT NULL, revoked_at TEXT, revision INTEGER);
   CREATE TABLE sessions (id TEXT NOT NULL, device_id TEXT NOT NULL, profile TEXT NOT NULL, uid INTEGER, root_pid INTEGER, root_start INTEGER, cgroup TEXT, boundary TEXT NOT NULL, verified INTEGER NOT NULL, state TEXT NOT NULL, started_at TEXT, ended_at TEXT, exit_code INTEGER, intent TEXT, close_requested_at TEXT, PRIMARY KEY (device_id, id));
   CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT);
   CREATE TRIGGER audit_append_only_u BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
   CREATE TRIGGER audit_append_only_d BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
   CREATE TABLE incidents (id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, device_id TEXT NOT NULL, session_id TEXT, process_instance TEXT, app TEXT, destination TEXT NOT NULL, port INTEGER, transport TEXT, reason TEXT NOT NULL, rule TEXT, policy_revision INTEGER, urgency TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('open','acknowledged','resolved')), occurrences INTEGER NOT NULL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, acknowledged_at TEXT, acknowledged_occurrences INTEGER, resolved_at TEXT, facts TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1);
   CREATE TABLE incident_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, type TEXT NOT NULL, source_ref TEXT, at TEXT NOT NULL, actor TEXT);
   CREATE INDEX incident_log_ref ON incident_log (incident_id, source_ref);
   CREATE TRIGGER incident_log_append_only_u BEFORE UPDATE ON incident_log BEGIN SELECT RAISE(ABORT, 'append-only'); END;
   CREATE TABLE notify_destinations (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('webhook','ntfy')), url TEXT NOT NULL, secret TEXT, min_urgency TEXT NOT NULL, created_at TEXT NOT NULL, disabled_at TEXT);
   CREATE TABLE notify_outbox (id TEXT PRIMARY KEY, dedup_key TEXT NOT NULL, destination_id TEXT NOT NULL, incident_id TEXT, opaque_ref TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT, last_error TEXT, UNIQUE (destination_id, dedup_key));
   CREATE TABLE notify_receipts (id TEXT PRIMARY KEY, outbox_id TEXT NOT NULL, attempt INTEGER NOT NULL, at TEXT NOT NULL, status INTEGER, outcome TEXT NOT NULL, detail TEXT);
   CREATE TABLE dns_clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, resolver TEXT NOT NULL, client TEXT NOT NULL, last_query_at TEXT, reachable INTEGER, policy TEXT, UNIQUE (resolver, client));
   CREATE TABLE dns_observations (id INTEGER PRIMARY KEY AUTOINCREMENT, resolver TEXT NOT NULL, client TEXT NOT NULL, name TEXT NOT NULL, qtype TEXT, answer_status TEXT, blocked INTEGER NOT NULL, at TEXT NOT NULL, UNIQUE (resolver, client, name, at));
   CREATE TABLE feed_cursor (name TEXT PRIMARY KEY, last_seq INTEGER NOT NULL);
   CREATE TABLE device_actions (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, kind TEXT NOT NULL, args TEXT NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT, done_at TEXT);`,
  // 2: timed trial revisions on endpoints (trial → confirmed | rolled_back).
  `CREATE TABLE device_revisions_v2 (device_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('approved','distributed','received','applied','verified','rejected','trial','confirmed','rolled_back')), at TEXT NOT NULL, detail TEXT, PRIMARY KEY (device_id, revision, state));
   INSERT INTO device_revisions_v2 SELECT * FROM device_revisions;
   DROP TABLE device_revisions;
   ALTER TABLE device_revisions_v2 RENAME TO device_revisions;`,
  // 3: the authorizer of each revision is recorded from the signer's answer (never assumed by a consumer).
  `ALTER TABLE policy_revisions ADD COLUMN authorized_by TEXT;`,
];

export function openDb(path: string, migrations: string[]): DB {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)");
  const row = db.prepare("SELECT v FROM schema_version").get() as { v: number } | undefined;
  let v = row?.v ?? 0;
  if (!row) db.prepare("INSERT INTO schema_version (v) VALUES (0)").run();
  for (; v < migrations.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(migrations[v]!);
      db.prepare("UPDATE schema_version SET v = ?").run(v + 1);
      db.exec("COMMIT");
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }
  return db;
}

export function tx<T>(db: DB, f: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const r = f();
    db.exec("COMMIT");
    return r;
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function audit(db: DB, now: Date, actor: string, action: string, target: string | null, detail: unknown): number {
  const r = db.prepare("INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)").run(now.toISOString(), actor, action, target, detail === undefined ? null : JSON.stringify(detail));
  return Number(r.lastInsertRowid);
}
