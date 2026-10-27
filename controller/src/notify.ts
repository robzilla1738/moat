/**
 * Notifier: durable outbox, retries with backoff, receipts, minimized payloads.
 *
 * Provenance: adapted from Digital Kingdom's notification outbox (robzilla1738/Digital-Kingdom@e0452c8,
 * apps/server/src/notify.ts, Apache-2.0): durable rows before delivery, (destination, dedup_key) uniqueness,
 * HMAC-signed webhook bodies, exponential backoff, visible failures.
 *
 * Moat additions:
 *  - `ntfy` destinations for instant phone delivery through an ntfy server (self-hosted, optionally with its
 *    APNs-connected upstream for iOS). The message carries ONLY an opaque reference; the phone fetches details from
 *    the controller over the tailnet after signing in. Using ntfy's upstream is an optional cloud transport
 *    dependency, disclosed in docs/privacy.md; without it the dashboard and foreground polling still work, but
 *    instant suspended-app delivery is not promised.
 *  - Notification limits never change enforcement: blocking is decided on the endpoint long before any of this.
 */
import { createHmac, randomBytes } from "node:crypto";
import { HttpError, type DB } from "./db.ts";

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{ status: number }>;
const URG = ["low", "medium", "high"] as const;
export type Urgency = (typeof URG)[number];

interface Dest { id: string; name: string; kind: "webhook" | "ntfy"; url: string; secret: string | null; min_urgency: Urgency; disabled_at: string | null }
interface Row { id: string; dedup_key: string; destination_id: string; incident_id: string | null; opaque_ref: string; payload: string; state: string; attempts: number; next_attempt_at: string; created_at: string; delivered_at: string | null; last_error: string | null }

export class Notifier {
  db: DB;
  now: () => Date;
  fetchImpl: FetchLike;
  publicUrl: string | null;
  constructor(db: DB, now: () => Date, fetchImpl: FetchLike, publicUrl: string | null) {
    this.db = db;
    this.now = now;
    this.fetchImpl = fetchImpl;
    this.publicUrl = publicUrl;
  }

  addDestination(b: { name?: unknown; kind?: unknown; url?: unknown; min_urgency?: unknown }) {
    const name = typeof b.name === "string" && b.name.trim() ? b.name.trim().slice(0, 80) : null;
    if (!name) throw new HttpError(400, "name is required");
    const kind = b.kind === "ntfy" ? "ntfy" : b.kind === "webhook" ? "webhook" : null;
    if (!kind) throw new HttpError(400, "kind must be webhook or ntfy");
    let u: URL;
    try {
      u = new URL(String(b.url));
    } catch {
      throw new HttpError(400, "url must be absolute");
    }
    if (u.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)) throw new HttpError(400, "destinations must use https (loopback http allowed for testing)");
    if (u.username || u.password) throw new HttpError(400, "credentials do not belong in the url");
    const min = URG.includes(b.min_urgency as Urgency) ? (b.min_urgency as Urgency) : "high";
    const id = `nd_${randomBytes(6).toString("hex")}`;
    const secret = kind === "webhook" ? randomBytes(32).toString("hex") : null;
    this.db.prepare("INSERT INTO notify_destinations (id, name, kind, url, secret, min_urgency, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, name, kind, u.toString(), secret, min, this.now().toISOString());
    return { id, name, kind, url_host: u.host, min_urgency: min, signing_secret: secret, cloud_dependency: kind === "ntfy" ? "If this ntfy server forwards to ntfy.sh/APNs for iOS delivery, an opaque reference transits that service. No incident details are sent." : null };
  }

  list() {
    return (this.db.prepare("SELECT id, name, kind, url, min_urgency, disabled_at FROM notify_destinations ORDER BY created_at").all() as unknown as Dest[]).map((d) => ({ id: d.id, name: d.name, kind: d.kind, url_host: new URL(d.url).host, min_urgency: d.min_urgency, disabled: !!d.disabled_at }));
  }

  /** Queue a notification for an incident. Payload is minimal; ntfy gets only the opaque reference. */
  enqueue(incidentId: string, dedupKey: string, urgency: Urgency, kind: string): string[] {
    const made: string[] = [];
    for (const d of this.db.prepare("SELECT * FROM notify_destinations WHERE disabled_at IS NULL").all() as unknown as Dest[]) {
      if (URG.indexOf(urgency) < URG.indexOf(d.min_urgency)) continue;
      const id = `no_${randomBytes(6).toString("hex")}`;
      const ref = randomBytes(12).toString("base64url");
      const link = this.publicUrl ? `${this.publicUrl.replace(/\/$/, "")}/#/r/${ref}` : null;
      const payload = d.kind === "ntfy" ? { message: "Moat needs a decision", ref, click: link } : { schema: "moat.notification.v1", kind, urgency, ref, link };
      const r = this.db
        .prepare("INSERT OR IGNORE INTO notify_outbox (id, dedup_key, destination_id, incident_id, opaque_ref, payload, state, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)")
        .run(id, dedupKey, d.id, incidentId, ref, JSON.stringify(payload), this.now().toISOString(), this.now().toISOString());
      if (r.changes) made.push(id);
    }
    return made;
  }

  /** Resolve an opaque reference to an incident id (the caller must be an authenticated owner). */
  resolveRef(ref: string): string | null {
    const r = this.db.prepare("SELECT incident_id FROM notify_outbox WHERE opaque_ref = ?").get(ref) as { incident_id: string | null } | undefined;
    return r?.incident_id ?? null;
  }

  async deliver(limit = 50) {
    const due = this.db.prepare("SELECT * FROM notify_outbox WHERE state = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?").all(this.now().toISOString(), limit) as unknown as Row[];
    let delivered = 0,
      failed = 0;
    for (const o of due) {
      const d = this.db.prepare("SELECT * FROM notify_destinations WHERE id = ?").get(o.destination_id) as unknown as Dest | undefined;
      if (!d || d.disabled_at) {
        this.db.prepare("UPDATE notify_outbox SET state = 'failed', last_error = 'destination disabled' WHERE id = ?").run(o.id);
        failed++;
        continue;
      }
      const attempt = o.attempts + 1;
      this.db.prepare("UPDATE notify_outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?").run(attempt, new Date(this.now().getTime() + 120_000).toISOString(), o.id);
      let status: number | null = null;
      let detail: string | null = null;
      try {
        const p = JSON.parse(o.payload) as { message?: string; click?: string | null };
        const res =
          d.kind === "ntfy"
            ? await this.fetchImpl(d.url, { method: "POST", headers: { "content-type": "text/plain", Title: "Moat", Priority: "high", ...(p.click ? { Click: p.click } : {}) }, body: `${p.message ?? "Moat"} (ref ${JSON.parse(o.payload).ref})`, signal: AbortSignal.timeout(10_000) })
            : await this.fetchImpl(d.url, { method: "POST", headers: { "content-type": "application/json", "x-moat-delivery-id": o.id, "x-moat-signature": `sha256=${createHmac("sha256", d.secret ?? "").update(o.payload).digest("hex")}` }, body: o.payload, signal: AbortSignal.timeout(10_000) });
        status = res.status;
      } catch (e) {
        detail = String((e as Error).message ?? e).slice(0, 200);
      }
      const ok = status !== null && status >= 200 && status < 300;
      this.db.prepare("INSERT INTO notify_receipts (id, outbox_id, attempt, at, status, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?)").run(`nr_${randomBytes(6).toString("hex")}`, o.id, attempt, this.now().toISOString(), status, ok ? "delivered" : "error", detail);
      if (ok) {
        this.db.prepare("UPDATE notify_outbox SET state = 'delivered', delivered_at = ?, last_error = NULL WHERE id = ?").run(this.now().toISOString(), o.id);
        delivered++;
      } else if (attempt >= 8) {
        this.db.prepare("UPDATE notify_outbox SET state = 'failed', last_error = ? WHERE id = ?").run(detail ?? `HTTP ${status}`, o.id);
        failed++;
      } else {
        this.db.prepare("UPDATE notify_outbox SET last_error = ?, next_attempt_at = ? WHERE id = ?").run(detail ?? `HTTP ${status}`, new Date(this.now().getTime() + Math.min(3600_000, 30_000 * 2 ** (attempt - 1))).toISOString(), o.id);
      }
    }
    return { attempted: due.length, delivered, failed };
  }

  status() {
    const rows = this.db.prepare("SELECT state, COUNT(*) AS n FROM notify_outbox GROUP BY state").all() as { state: string; n: number }[];
    return { counts: Object.fromEntries(rows.map((r) => [r.state, r.n])), note: "Delivery describes the outbox, not whether anyone acted. A delivered notification is not a resolved incident." };
  }
}
