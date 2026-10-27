/**
 * W16: operational DNS adapters for AdGuard Home and Pi-hole, kept optional to desktop enforcement.
 *
 * Each configured resolver gets a poller with:
 *  - a supported-version check before any ingest (an unsupported or unknown version is refused, never guessed at);
 *  - its own authentication (AdGuard Home basic auth; a Pi-hole v6 session id, re-authenticated once on 401);
 *  - a durable checkpoint (AdGuard: newest query time plus the keys seen at that instant; Pi-hole: newest query id);
 *  - deduplication (the checkpoint, plus unique keys in storage), so a restart never duplicates or invents events;
 *  - bounded polling (page size, page budget, per-request timeout, minimum interval, exponential backoff);
 *  - gap detection: history the poll budget did not reach, history the resolver no longer has (retention, log
 *    cleared) and a Pi-hole database reset are recorded as declared gaps, never silently skipped;
 *  - health: ok / auth_failed / unsupported_version / unreachable / error, with the last good poll time.
 *
 * What DNS evidence is: a client address asked a resolver for a name, and the resolver answered or blocked it. It
 * is never an app, a process, a completed connection or a byte count, and it says nothing about direct-IP traffic
 * or other encrypted-DNS paths. Records and clients produced here stay labeled `dns-only`.
 *
 * API shapes follow AdGuard Home v0.107 (`/control/status`, `/control/querylog` with `older_than`/`limit`, response
 * `{data, oldest}`) and Pi-hole v6 (`/api/auth`, `/api/info/version`, `/api/queries` with `length`/`start`/`cursor`,
 * response `{queries, cursor, recordsTotal}`). The test fixtures are shaped after those documented APIs; they were
 * not captured from a live resolver (see docs/integrations.md).
 */
import type { DB } from "./db.ts";
import type { DnsObservation } from "./dns.ts";

export type Health = "ok" | "auth_failed" | "unsupported_version" | "unreachable" | "error" | "never_polled";

export interface ResolverSettings {
  id: string;
  kind: "adguard" | "pihole";
  url: string;
  username?: string;
  password?: string;
  /** Entries per page (bounded 1..1000). */
  pageSize?: number;
  /** Pages per poll (bounded 1..20); history beyond it in one poll becomes a declared gap. */
  maxPages?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Minimum time between polls, and the base of the failure backoff. */
  intervalMs?: number;
}

export interface HttpResponse { status: number; json(): Promise<unknown> }
export type HttpFetch = (url: string, init: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<HttpResponse>;

export interface Gap { from: string | null; to: string | null; reason: string }
export interface PollResult {
  resolver: string;
  health: Health;
  version: string | null;
  observations: DnsObservation[];
  stored: number;
  gaps: Gap[];
  pages: number;
  error: string | null;
}

export const SUPPORTED = {
  adguard: { label: "AdGuard Home v0.107.x", test: (v: string) => /^v?0\.107\.\d+/.test(v) },
  pihole: { label: "Pi-hole FTL v6.x", test: (v: string) => /^v?6\.\d+/.test(v) },
} as const;

const MAX_BACKOFF_MS = 30 * 60_000;

class HttpStatusError extends Error {
  status: number;
  constructor(status: number, what: string) {
    super(`${what}: HTTP ${status}`);
    this.status = status;
  }
}

function clamp(v: number | undefined, lo: number, hi: number, d: number) {
  return Math.min(hi, Math.max(lo, Math.floor(v ?? d)));
}

/** AdGuard querylog entry → observation (client may be absent when the resolver anonymizes clients). */
function adguardObservation(resolver: string, e: Record<string, unknown>): (DnsObservation & { key: string; rawTime: string }) | null {
  const q = (e.question ?? {}) as { name?: string; type?: string };
  if (!q.name || typeof e.client !== "string" || typeof e.time !== "string" || Number.isNaN(Date.parse(e.time))) return null;
  const reason = String(e.reason ?? "");
  const name = q.name.replace(/\.$/, "").toLowerCase();
  return {
    resolver,
    client: e.client,
    name,
    qtype: q.type ?? null,
    answer_status: typeof e.status === "string" ? e.status : null,
    blocked: reason.startsWith("Filtered") && reason !== "FilteredSafeSearch",
    at: new Date(e.time).toISOString(),
    rawTime: e.time,
    key: `${e.time}|${e.client}|${name}|${q.type ?? ""}`,
  };
}

function piholeObservation(resolver: string, q: Record<string, unknown>): (DnsObservation & { id: number }) | null {
  const client = (q.client as { ip?: string } | undefined)?.ip;
  if (typeof q.domain !== "string" || !client || typeof q.time !== "number" || typeof q.id !== "number") return null;
  const status = String(q.status ?? "");
  return {
    resolver,
    client,
    name: q.domain.toLowerCase(),
    qtype: typeof q.type === "string" ? q.type : null,
    answer_status: status,
    blocked: /GRAVITY|BLACKLIST|DENYLIST|REGEX|EXTERNAL_BLOCKED|SPECIAL_DOMAIN/.test(status),
    at: new Date(q.time * 1000).toISOString(),
    id: q.id,
  };
}

interface AdguardCheckpoint { newest_at: string; keys: string[] }
interface PiholeCheckpoint { last_id: number; last_at: string | null }
interface StateRow { resolver: string; kind: string; version: string | null; checkpoint: string | null; health: string; last_ok_at: string | null; last_attempt_at: string | null; last_error: string | null; failures: number; next_poll_at: string | null; started_at: string | null }

export class ResolverPoller {
  db: DB;
  cfg: Required<Omit<ResolverSettings, "username" | "password">> & { username?: string; password?: string };
  fetchImpl: HttpFetch;
  now: () => Date;
  private sid: string | null = null;

  constructor(db: DB, cfg: ResolverSettings, fetchImpl: HttpFetch, now: () => Date = () => new Date()) {
    if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(cfg.id)) throw new Error("resolver id must be lowercase letters, digits and dashes");
    if (!/^https?:\/\//.test(cfg.url)) throw new Error("resolver url must be http(s)");
    this.db = db;
    this.cfg = {
      ...cfg,
      url: cfg.url.replace(/\/$/, ""),
      pageSize: clamp(cfg.pageSize, 1, 1000, 500),
      maxPages: clamp(cfg.maxPages, 1, 20, 5),
      timeoutMs: clamp(cfg.timeoutMs, 100, 60_000, 10_000),
      intervalMs: clamp(cfg.intervalMs, 1_000, 3_600_000, 30_000),
    };
    this.fetchImpl = fetchImpl;
    this.now = now;
    db.prepare("INSERT OR IGNORE INTO dns_adapter_state (resolver, kind, health, failures) VALUES (?, ?, 'never_polled', 0)").run(cfg.id, cfg.kind);
  }

  state(): StateRow {
    return this.db.prepare("SELECT * FROM dns_adapter_state WHERE resolver = ?").get(this.cfg.id) as unknown as StateRow;
  }

  /** Bounded polling: not before the interval, and with exponential backoff after failures. */
  due(): boolean {
    const s = this.state();
    return !s.next_poll_at || Date.parse(s.next_poll_at) <= this.now().getTime();
  }

  private async get(path: string, headers: Record<string, string> = {}, method = "GET", body?: string): Promise<unknown> {
    const r = await this.fetchImpl(`${this.cfg.url}${path}`, { method, headers, body, signal: AbortSignal.timeout(this.cfg.timeoutMs) });
    if (r.status !== 200) throw new HttpStatusError(r.status, `${method} ${path.split("?")[0]}`);
    return r.json();
  }

  // ---------------------------------------------------------------- AdGuard Home
  private adguardAuth(): Record<string, string> {
    return this.cfg.username || this.cfg.password ? { authorization: `Basic ${Buffer.from(`${this.cfg.username ?? ""}:${this.cfg.password ?? ""}`).toString("base64")}` } : {};
  }

  private async adguardVersion(): Promise<string> {
    const s = (await this.get("/control/status", this.adguardAuth())) as { version?: unknown };
    return typeof s.version === "string" ? s.version : "";
  }

  private async adguardPoll(cp: AdguardCheckpoint | null) {
    const out: (DnsObservation & { key: string; rawTime: string })[] = [];
    const gaps: Gap[] = [];
    let olderThan: string | null = null;
    let pages = 0;
    let reached = cp === null; // first poll imports one page and records where history starts
    let exhausted = false;
    let oldestFetched: string | null = null;
    const cpMs = cp ? Date.parse(cp.newest_at) : 0;
    const seenAtCp = new Set(cp?.keys ?? []);
    while (pages < this.cfg.maxPages) {
      const q = `/control/querylog?limit=${this.cfg.pageSize}${olderThan ? `&older_than=${encodeURIComponent(olderThan)}` : ""}`;
      const page = (await this.get(q, this.adguardAuth())) as { data?: unknown[]; oldest?: string };
      pages++;
      const rows = (page.data ?? []) as Record<string, unknown>[];
      for (const e of rows) {
        const o = adguardObservation(this.cfg.id, e);
        if (!o) continue;
        oldestFetched = o.rawTime;
        const ms = Date.parse(o.rawTime);
        if (cp && (ms < cpMs || (ms === cpMs && seenAtCp.has(o.key)))) {
          reached = true;
          continue;
        }
        out.push(o);
      }
      if (reached || cp === null) break;
      if (rows.length < this.cfg.pageSize || !page.oldest) {
        exhausted = true;
        break;
      }
      olderThan = page.oldest;
    }
    if (cp && !reached) {
      gaps.push(exhausted
        ? { from: cp.newest_at, to: oldestFetched, reason: "the resolver no longer has these queries (log retention or a cleared log)" }
        : { from: cp.newest_at, to: oldestFetched, reason: `more history than the poll budget (${this.cfg.maxPages} pages of ${this.cfg.pageSize}); queries in this window were not imported` });
    }
    // checkpoint: the newest instant and every key seen exactly at it (same-millisecond queries are not lost)
    let next = cp;
    if (out.length) {
      const newestMs = Math.max(...out.map((o) => Date.parse(o.rawTime)));
      const atNewest = out.filter((o) => Date.parse(o.rawTime) === newestMs);
      const keys = new Set(atNewest.map((o) => o.key));
      if (cp && Date.parse(cp.newest_at) === newestMs) for (const k of cp.keys) keys.add(k);
      next = { newest_at: atNewest[0]!.rawTime, keys: [...keys].slice(-2000) };
    }
    return { obs: out, gaps, pages, checkpoint: next, startedAt: cp === null && out.length ? out[out.length - 1]!.at : null };
  }

  // ---------------------------------------------------------------- Pi-hole v6
  private async piholeLogin(): Promise<void> {
    const r = (await this.get("/api/auth", { "content-type": "application/json" }, "POST", JSON.stringify({ password: this.cfg.password ?? "" }))) as { session?: { valid?: boolean; sid?: string | null; message?: string } };
    if (!r.session?.valid) throw new HttpStatusError(401, `pi-hole authentication refused (${r.session?.message ?? "invalid password"})`);
    this.sid = r.session.sid ?? null;
  }

  private async piholeGet(path: string): Promise<unknown> {
    if (this.sid === null) await this.piholeLogin();
    try {
      return await this.get(path, this.sid ? { sid: this.sid } : {});
    } catch (e) {
      if (!(e instanceof HttpStatusError) || e.status !== 401) throw e;
      await this.piholeLogin(); // the session expired: one re-authentication, then a real failure
      return this.get(path, this.sid ? { sid: this.sid } : {});
    }
  }

  private async piholeVersion(): Promise<string> {
    const v = (await this.piholeGet("/api/info/version")) as { version?: { ftl?: { local?: { version?: string } } } };
    return v.version?.ftl?.local?.version ?? "";
  }

  private async piholePoll(cp: PiholeCheckpoint | null) {
    const out: (DnsObservation & { id: number })[] = [];
    const gaps: Gap[] = [];
    let pages = 0;
    let cursor: number | null = null;
    let reached = cp === null;
    let exhausted = false;
    let reset = false;
    let maxId = -1;
    while (pages < this.cfg.maxPages) {
      const q = `/api/queries?length=${this.cfg.pageSize}&start=${pages * this.cfg.pageSize}${cursor !== null ? `&cursor=${cursor}` : ""}`;
      const page = (await this.piholeGet(q)) as { queries?: unknown[]; cursor?: number };
      if (cursor === null && typeof page.cursor === "number") cursor = page.cursor;
      pages++;
      const rows = (page.queries ?? []) as Record<string, unknown>[];
      for (const r of rows) {
        const o = piholeObservation(this.cfg.id, r);
        if (!o) continue;
        maxId = Math.max(maxId, o.id);
        if (cp && o.id <= cp.last_id) {
          reached = true;
          continue;
        }
        out.push(o);
      }
      if (pages === 1 && cp && maxId >= 0 && maxId < cp.last_id) {
        reset = true; // ids went backwards: the FTL database was replaced or flushed
        break;
      }
      if (reached || cp === null) break;
      if (rows.length < this.cfg.pageSize) {
        exhausted = true;
        break;
      }
    }
    const minFetched = out.length ? Math.min(...out.map((o) => o.id)) : null;
    if (reset) gaps.push({ from: cp!.last_at, to: null, reason: `the resolver's query ids went backwards (newest ${maxId} < checkpoint ${cp!.last_id}): its database was reset; earlier history is gone` });
    else if (cp && !reached && minFetched !== null && minFetched > cp.last_id + 1) {
      gaps.push(exhausted
        ? { from: cp.last_at, to: out.find((o) => o.id === minFetched)!.at, reason: `queries ${cp.last_id + 1}..${minFetched - 1} are no longer on the resolver (retention or flush)` }
        : { from: cp.last_at, to: out.find((o) => o.id === minFetched)!.at, reason: `queries ${cp.last_id + 1}..${minFetched - 1} exceed the poll budget (${this.cfg.maxPages} pages of ${this.cfg.pageSize}) and were not imported` });
    }
    let next: PiholeCheckpoint | null = reset ? null : cp;
    if (out.length) {
      const top = out.reduce((a, b) => (b.id > a.id ? b : a));
      next = { last_id: top.id, last_at: top.at };
    }
    return { obs: out, gaps, pages, checkpoint: next, startedAt: (cp === null || reset) && out.length ? out.reduce((a, b) => (b.id < a.id ? b : a)).at : null };
  }

  // ---------------------------------------------------------------- one bounded poll
  async poll(): Promise<PollResult> {
    const st = this.state();
    const at = this.now();
    const base: PollResult = { resolver: this.cfg.id, health: "error", version: st.version, observations: [], stored: 0, gaps: [], pages: 0, error: null };
    try {
      const version = this.cfg.kind === "adguard" ? await this.adguardVersion() : await this.piholeVersion();
      const sup = SUPPORTED[this.cfg.kind];
      if (!version || !sup.test(version)) {
        return this.finish({ ...base, health: "unsupported_version", version: version || null, error: `${version ? `version ${version}` : "no version reported"}; supported: ${sup.label}. Nothing was ingested.` }, at, st, null);
      }
      const cp = st.checkpoint ? JSON.parse(st.checkpoint) : null;
      const r = this.cfg.kind === "adguard" ? await this.adguardPoll(cp as AdguardCheckpoint | null) : await this.piholePoll(cp as PiholeCheckpoint | null);
      const obs = r.obs.map(({ ...o }) => {
        const clean: DnsObservation & { source_id?: string } = { resolver: o.resolver, client: o.client, name: o.name, qtype: o.qtype, answer_status: o.answer_status, blocked: o.blocked, at: o.at };
        if ("id" in o) clean.source_id = String((o as { id: number }).id);
        return clean;
      });
      return this.finish({ ...base, health: "ok", version, observations: obs, gaps: r.gaps, pages: r.pages }, at, st, { checkpoint: r.checkpoint, startedAt: r.startedAt });
    } catch (e) {
      const status = e instanceof HttpStatusError ? e.status : null;
      const health: Health = status === 401 || status === 403 ? "auth_failed" : status === null ? "unreachable" : status === 404 ? "unsupported_version" : "error";
      const msg = status === 404 ? `${(e as Error).message}: endpoint missing (an older API, e.g. Pi-hole v5, is not supported)` : String((e as Error).message ?? e);
      if (health === "auth_failed") this.sid = null;
      return this.finish({ ...base, health, error: msg }, at, st, null);
    }
  }

  private finish(r: PollResult, at: Date, st: StateRow, ok: { checkpoint: unknown; startedAt: string | null } | null): PollResult {
    const iso = at.toISOString();
    if (ok) {
      // ingest, checkpoint and gaps commit together: a crash before commit re-polls from the old checkpoint, and
      // storage keys deduplicate whatever was already stored
      this.db.exec("BEGIN IMMEDIATE");
      try {
        r.stored = storeDeduped(this.db, r.observations, this.cfg.id);
        for (const g of r.gaps) this.db.prepare("INSERT INTO dns_gaps (resolver, from_at, to_at, reason, detected_at) VALUES (?, ?, ?, ?, ?)").run(this.cfg.id, g.from, g.to, g.reason, iso);
        this.db.prepare("UPDATE dns_adapter_state SET version = ?, checkpoint = ?, health = 'ok', last_ok_at = ?, last_attempt_at = ?, last_error = NULL, failures = 0, next_poll_at = ?, started_at = COALESCE(started_at, ?) WHERE resolver = ?")
          .run(r.version, ok.checkpoint === null ? null : JSON.stringify(ok.checkpoint), iso, iso, new Date(at.getTime() + this.cfg.intervalMs).toISOString(), ok.startedAt, this.cfg.id);
        this.db.prepare("UPDATE dns_clients SET reachable = 1 WHERE resolver = ?").run(this.cfg.id);
        this.db.exec("COMMIT");
      } catch (e) {
        this.db.exec("ROLLBACK");
        throw e;
      }
      return r;
    }
    const failures = st.failures + 1;
    const backoff = Math.min(MAX_BACKOFF_MS, this.cfg.intervalMs * 2 ** Math.min(failures, 10));
    this.db.prepare("UPDATE dns_adapter_state SET version = COALESCE(?, version), health = ?, last_attempt_at = ?, last_error = ?, failures = ?, next_poll_at = ? WHERE resolver = ?")
      .run(r.version, r.health, iso, r.error, failures, new Date(at.getTime() + backoff).toISOString(), this.cfg.id);
    // the resolver's clients are not known to be unreachable, but nothing about them is current: mark them so
    this.db.prepare("UPDATE dns_clients SET reachable = 0 WHERE resolver = ?").run(this.cfg.id);
    return r;
  }
}

/** Store observations; a repeat (same resolver id, or same resolver/client/name/instant) is ignored. */
export function storeDeduped(db: DB, obs: (DnsObservation & { source_id?: string })[], resolver: string): number {
  const ins = db.prepare("INSERT OR IGNORE INTO dns_observations (resolver, client, name, qtype, answer_status, blocked, at, source_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  const cli = db.prepare("INSERT INTO dns_clients (id, name, resolver, client, last_query_at, reachable) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT (resolver, client) DO UPDATE SET last_query_at = MAX(COALESCE(dns_clients.last_query_at, ''), excluded.last_query_at), reachable = 1");
  let n = 0;
  for (const o of obs) {
    n += Number(ins.run(resolver, o.client, o.name, o.qtype, o.answer_status, o.blocked ? 1 : 0, o.at, o.source_id ?? null).changes);
    cli.run(`${resolver}:${o.client}`, o.client, resolver, o.client, o.at);
  }
  return n;
}

/** Health for the UI and API: the state row, its open gaps and the evidence age (computed, never a stored label). */
export function resolverHealth(db: DB, now: Date) {
  const rows = db.prepare("SELECT * FROM dns_adapter_state ORDER BY resolver").all() as unknown as StateRow[];
  return rows.map((s) => ({
    resolver: s.resolver,
    kind: s.kind,
    version: s.version,
    supported: SUPPORTED[s.kind as "adguard" | "pihole"]?.label ?? null,
    health: s.health as Health,
    last_ok_at: s.last_ok_at,
    last_attempt_at: s.last_attempt_at,
    last_error: s.last_error,
    consecutive_failures: s.failures,
    next_poll_at: s.next_poll_at,
    history_starts_at: s.started_at,
    evidence_age_s: s.last_ok_at ? Math.max(0, Math.round((now.getTime() - Date.parse(s.last_ok_at)) / 1000)) : null,
    gaps: db.prepare("SELECT from_at, to_at, reason, detected_at FROM dns_gaps WHERE resolver = ? ORDER BY id DESC LIMIT 20").all(s.resolver),
  }));
}

/**
 * A blocked query becomes a `dns_blocked` incident on the DNS-only client (`dns:<resolver>:<client>`): never on an
 * enrolled endpoint, never with an app, process, port or bytes. Repeats group; a re-poll of the same query is ignored.
 */
export function raiseDnsBlocks(raise: (s: { kind: string; device: string; destination: string; reason: string; urgency: "low" | "medium" | "high"; ref: string; at: string; facts?: Record<string, unknown> }) => unknown, obs: (DnsObservation & { source_id?: string })[]) {
  let n = 0;
  for (const o of obs) {
    if (!o.blocked) continue;
    raise({
      kind: "dns_blocked",
      device: `dns:${o.resolver}:${o.client}`,
      destination: o.name,
      reason: `resolver ${o.resolver} blocked this name for ${o.client} (DNS-only evidence: no app, process, connection or byte count)`,
      urgency: "low",
      ref: `dns:${o.resolver}:${o.source_id ?? `${o.at}|${o.client}|${o.name}|${o.qtype ?? ""}`}`,
      at: o.at,
      facts: { coverage: "dns-only", qtype: o.qtype, answer_status: o.answer_status },
    });
    n++;
  }
  return n;
}
