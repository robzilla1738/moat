/**
 * DNS-only coverage for phones and the TV via AdGuard Home or Pi-hole running as an independent service.
 *
 * What DNS can establish: which client (if the resolver preserves client identity) asked for which name, when, and
 * whether the resolver blocked it. What it cannot: the originating app or process, a completed connection, transfer
 * size, or anything about direct-IP or alternative encrypted-DNS traffic. Records produced here therefore carry no
 * process, no app and no byte counts, and every client is labeled `dns-only`.
 */
import type { DB } from "./db.ts";

export interface DnsObservation { resolver: string; client: string; name: string; qtype: string | null; answer_status: string | null; blocked: boolean; at: string }
export type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{ status: number; json(): Promise<unknown> }>;

/** AdGuard Home `/control/querylog` (basic auth). */
export function parseAdGuardQueryLog(resolver: string, body: unknown): DnsObservation[] {
  const data = (body as { data?: unknown[] })?.data ?? [];
  const out: DnsObservation[] = [];
  for (const e of data as Record<string, unknown>[]) {
    const q = (e.question ?? {}) as { name?: string; type?: string };
    if (!q.name || typeof e.client !== "string" || typeof e.time !== "string") continue;
    const reason = String(e.reason ?? "");
    out.push({ resolver, client: e.client, name: q.name.replace(/\.$/, "").toLowerCase(), qtype: q.type ?? null, answer_status: typeof e.status === "string" ? e.status : null, blocked: reason.startsWith("Filtered") || reason === "FilteredBlackList", at: new Date(e.time).toISOString() });
  }
  return out;
}

/** Pi-hole v6 `/api/queries` (session id from `/api/auth`). */
export function parsePiholeQueries(resolver: string, body: unknown): DnsObservation[] {
  const qs = (body as { queries?: unknown[] })?.queries ?? [];
  const out: DnsObservation[] = [];
  for (const q of qs as Record<string, unknown>[]) {
    const client = (q.client as { ip?: string } | undefined)?.ip;
    if (typeof q.domain !== "string" || !client || typeof q.time !== "number") continue;
    const status = String(q.status ?? "");
    out.push({ resolver, client, name: q.domain.toLowerCase(), qtype: typeof q.type === "string" ? q.type : null, answer_status: status, blocked: /GRAVITY|BLACKLIST|DENYLIST|REGEX|EXTERNAL_BLOCKED|SPECIAL_DOMAIN/.test(status), at: new Date(q.time * 1000).toISOString() });
  }
  return out;
}

export interface ResolverConfig { id: string; kind: "adguard" | "pihole"; url: string; username?: string; password?: string }

export async function pollResolver(cfg: ResolverConfig, fetchImpl: Fetch): Promise<{ reachable: boolean; observations: DnsObservation[]; error?: string }> {
  try {
    if (cfg.kind === "adguard") {
      const auth = Buffer.from(`${cfg.username ?? ""}:${cfg.password ?? ""}`).toString("base64");
      const r = await fetchImpl(`${cfg.url.replace(/\/$/, "")}/control/querylog?limit=500`, { headers: { authorization: `Basic ${auth}` } });
      if (r.status !== 200) return { reachable: true, observations: [], error: `HTTP ${r.status}` };
      return { reachable: true, observations: parseAdGuardQueryLog(cfg.id, await r.json()) };
    }
    const a = await fetchImpl(`${cfg.url.replace(/\/$/, "")}/api/auth`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password: cfg.password ?? "" }) });
    const sid = ((await a.json()) as { session?: { sid?: string } })?.session?.sid;
    if (!sid) return { reachable: true, observations: [], error: "pi-hole authentication failed" };
    const r = await fetchImpl(`${cfg.url.replace(/\/$/, "")}/api/queries?length=500`, { headers: { sid } });
    return { reachable: true, observations: parsePiholeQueries(cfg.id, await r.json()) };
  } catch (e) {
    return { reachable: false, observations: [], error: String((e as Error).message ?? e) };
  }
}

export function storeObservations(db: DB, obs: DnsObservation[], reachable: boolean, resolver: string) {
  const ins = db.prepare("INSERT OR IGNORE INTO dns_observations (resolver, client, name, qtype, answer_status, blocked, at) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const cli = db.prepare("INSERT INTO dns_clients (id, name, resolver, client, last_query_at, reachable) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (resolver, client) DO UPDATE SET last_query_at = MAX(COALESCE(dns_clients.last_query_at, ''), excluded.last_query_at), reachable = excluded.reachable");
  let n = 0;
  for (const o of obs) {
    n += Number(ins.run(o.resolver, o.client, o.name, o.qtype, o.answer_status, o.blocked ? 1 : 0, o.at).changes);
    cli.run(`${o.resolver}:${o.client}`, o.client, o.resolver, o.client, o.at, reachable ? 1 : 0);
  }
  db.prepare("UPDATE dns_clients SET reachable = ? WHERE resolver = ?").run(reachable ? 1 : 0, resolver);
  return n;
}

export function dnsClients(db: DB) {
  return (db.prepare("SELECT * FROM dns_clients ORDER BY last_query_at DESC").all() as Record<string, unknown>[]).map((c) => ({
    ...c,
    coverage: "dns-only",
    claim: "Resolver queries from this client. No app, process, connection or byte count is known; direct-IP and alternative encrypted DNS are not covered.",
  }));
}
