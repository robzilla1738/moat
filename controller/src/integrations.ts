/**
 * W16 wiring: the configured DNS resolvers and the Digital Kingdom feed, both optional to desktop enforcement.
 *
 * Configuration (moat-controller serve):
 *   MOAT_RESOLVERS_FILE  JSON array of { id, kind: "adguard" | "pihole", url, username?, password_file?, page_size?,
 *                        max_pages?, timeout_ms?, interval_ms? }. Passwords are read from password_file (never stored
 *                        in the controller database or returned by the API).
 *   MOAT_DK_URL + MOAT_DK_SOURCE_KEY_FILE   Digital Kingdom ingest URL and Moat's source key.
 *
 * A blocked DNS query becomes a `dns_blocked` incident on the DNS-only client `dns:<resolver>:<client>`: never on an
 * enrolled endpoint and never with an app, process, port or bytes. Only queries stored for the first time raise, so a
 * restart or re-poll does not duplicate incidents.
 */
import { readFileSync } from "node:fs";
import type { Controller } from "./controller.ts";
import { DkFeed, producerRegistration } from "./dkfeed.ts";
import type { FetchLike } from "./notify.ts";
import { HttpError } from "./db.ts";
import { raiseDnsBlocks, resolverHealth, ResolverPoller, type HttpFetch, type ResolverSettings } from "./resolvers.ts";

export interface ResolverFileEntry { id: string; kind: "adguard" | "pihole"; url: string; username?: string; password_file?: string; page_size?: number; max_pages?: number; timeout_ms?: number; interval_ms?: number }

/** Parse MOAT_RESOLVERS_FILE content; unknown kinds and duplicate ids are configuration errors, not skipped. */
export function parseResolverConfig(text: string, readSecret: (path: string) => string = (p) => readFileSync(p, "utf8").trim()): ResolverSettings[] {
  const arr = JSON.parse(text) as ResolverFileEntry[];
  if (!Array.isArray(arr)) throw new Error("resolver config must be a JSON array");
  const seen = new Set<string>();
  return arr.map((e) => {
    if (e.kind !== "adguard" && e.kind !== "pihole") throw new Error(`resolver ${e.id}: kind must be adguard or pihole`);
    if (seen.has(e.id)) throw new Error(`resolver ${e.id} is configured twice`);
    seen.add(e.id);
    return { id: e.id, kind: e.kind, url: e.url, username: e.username, password: e.password_file ? readSecret(e.password_file) : undefined, pageSize: e.page_size, maxPages: e.max_pages, timeoutMs: e.timeout_ms, intervalMs: e.interval_ms };
  });
}

export class Integrations {
  c: Controller;
  resolvers = new Map<string, ResolverPoller>();
  dk: DkFeed | null = null;
  constructor(c: Controller) {
    this.c = c;
  }

  configureResolvers(settings: ResolverSettings[], fetchImpl: HttpFetch) {
    for (const s of settings) this.resolvers.set(s.id, new ResolverPoller(this.c.db, s, fetchImpl, this.c.now));
  }

  configureDk(url: string, sourceKey: string, fetchImpl: FetchLike) {
    this.dk = new DkFeed(this.c.db, url, sourceKey, fetchImpl, this.c.now);
  }

  /** Poll one resolver now and raise incidents for newly stored blocked queries. */
  async pollResolver(id: string) {
    const p = this.resolvers.get(id);
    if (!p) throw new HttpError(404, `no resolver ${id} is configured`);
    const r = await p.poll();
    const raised = raiseDnsBlocks((s) => this.c.raise(s), r.fresh);
    return { resolver: r.resolver, health: r.health, version: r.version, stored: r.stored, raised, gaps: r.gaps, pages: r.pages, error: r.error };
  }

  /** Poll every resolver whose interval/backoff has elapsed. */
  async pollDue() {
    const out = [];
    for (const [id, p] of this.resolvers) if (p.due()) out.push(await this.pollResolver(id));
    return out;
  }

  /** Resolver health for the API. Configured-but-never-polled resolvers appear with health never_polled. */
  resolverStatus() {
    return resolverHealth(this.c.db, this.c.now()).map((h) => ({ ...h, configured: this.resolvers.has(h.resolver) }));
  }

  dkStatus() {
    return {
      configured: !!this.dk,
      registration: producerRegistration(this.c.db),
      health: this.dk ? this.dk.health() : null,
      claim: "Moat reports as one agent_observer source: endpoint policy decisions (policy enforcer), coverage loss and self-reported intent. DNS-only evidence is not sent, and agent intent never carries an enforcement outcome.",
    };
  }
}
