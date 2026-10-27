/**
 * Live mode: read the Moat controller's API and map it onto the UI model. Nothing here falls back to demo data:
 * anything the controller does not provide stays empty, and every failure is reported as a failure.
 */
import type { App, Capability, Coverage, Device, Incident, Platform, Revision, RevisionState, Session, Snapshot, Support } from "./types";

export const TOKEN_KEY = "moat.token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
  /** 0 = the request never got an HTTP answer (offline, DNS, TLS, CORS, abort). */
  get offline() {
    return this.status === 0;
  }
}

export interface Api {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body: unknown): Promise<T>;
}

export function makeApi(token: string, fetchImpl: typeof fetch = (...a) => fetch(...a), timeoutMs = 15_000): Api {
  const call = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    let r: Response;
    try {
      r = await fetchImpl(path, {
        method,
        headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
        cache: "no-store",
      });
    } catch (e) {
      throw new ApiError(0, `controller unreachable (${(e as Error).message || "network error"})`);
    }
    let j: unknown = null;
    try {
      j = await r.json();
    } catch {
      if (r.ok) throw new ApiError(r.status, "controller sent a response that is not JSON");
    }
    if (!r.ok) throw new ApiError(r.status, (j as { error?: string } | null)?.error ?? `HTTP ${r.status}`);
    return j as T;
  };
  return { get: (p) => call("GET", p), post: (p, b) => call("POST", p, b ?? {}) };
}

// ---------------------------------------------------------------- wire types (controller JSON)
export interface WireOverview { server_time: string; revision: number | null }
export interface WireMe { id: string; name: string; role: "owner" | "viewer" | "launcher" | "agent" }
export interface WireDevice { id: string; name: string; platform: string; coverage: string | null; last_seen_at: string | null; last_revision: number | null; telemetry_gaps: [number, number][]; capabilities: { capabilities?: Record<string, { support?: string; note?: string }> } | null; status: { coverage_note?: string; os?: string } | null; revision_states: { revision: number; state: string; at: string; detail: string | null }[]; awaiting_retarget?: boolean }
export interface WireIncident { id: string; revision: number; kind: Incident["kind"]; urgency: Incident["urgency"]; state: Incident["state"]; device_id: string; session_id: string | null; process_instance: string | null; app: string | null; destination: string; port: number | null; transport: string | null; reason: string; rule: string | null; policy_revision: number | null; occurrences: number; first_at: string; last_at: string; facts: { chain?: string[] | null; transfer?: { bytes_out?: number; bytes_in?: number; source?: string } | null } | null }
export interface WireRevision { revision: number; created_at: string; approved_by: string; authorized_by: Revision["authorizedBy"]; owner_key_id: string | null; rollback_of: number | null; source_digest: string; message: string | null; grants: string[]; devices: { device_id: string; state: string; at: string; detail: string | null }[]; platforms: { platform: string; report: { omitted?: unknown[]; unavailable_session_profiles?: string[] } | null }[] }
export interface WireSession { id: string; device_id: string; profile: string; boundary: string; verified: number; state: string; started_at: string; ended_at: string | null; intent: string | null; close_requested_at: string | null }
export interface WireGrant { id: string; kind: string; device_id: string | null; session_id: string | null; process_instance: string | null; destination: string; transport: string; port: number | null; expires_at: string; created_by: string; state: string }
export interface WireApp { id: string; name: string; family: string | null; exe: string | null; signer: string | null; identity: "executable" | "unknown"; devices: string[]; sessions: number; flows: number; denied: number; observed: number; destinations: { host: string; port: number | null; count: number; verdict: "allow" | "deny" | "observed"; firstAt: string; lastAt: string; new: boolean }[]; lastActive: string; firstSeen: string }
export interface WireRollup { hour: string; verdict: string; flows: number }
export interface WireGrantStatus { id: string; state: "pending" | "active" | "rejected" | "expired" | "revoked"; revision: number | null; authorized_by: string | null; expires_at: string; devices: { device_id: string; state: string; stale: boolean; evidence: { revision: number; state: string; at: string; detail: string | null } | null }[]; server_time: string }
export interface WireProposal { id: string; broadening: boolean; status: string; base_revision: number | null; rollback_of: number | null; message: string; authorization_subject: string; authorization_digest: string; diff: Record<string, unknown> }

const COVERAGES: Record<string, Coverage> = { "protected-session": "protected-session", protected_session: "protected-session", "emergency-isolation": "isolated", isolated: "isolated", degraded: "degraded", enforced: "enforced", monitoring: "monitoring", observing: "monitoring", "dns-only": "dns-only" };
export const coverageOf = (c: string | null): Coverage => (c && COVERAGES[c]) || "unknown";
const SUPPORTS: Support[] = ["supported", "partial", "untested", "unsupported"];
const platformOf = (p: string): Platform => (p === "macos" ? "macos" : p === "ios" ? "ios" : p === "android-tv" ? "android-tv" : "linux");
const human = (k: string) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

export function mapDevice(d: WireDevice): Device {
  const caps: Capability[] = Object.entries(d.capabilities?.capabilities ?? {}).map(([key, v]) => ({ key, label: human(key), support: SUPPORTS.includes(v.support as Support) ? (v.support as Support) : "untested", note: v.note }));
  const latest = d.revision_states[0];
  return {
    id: d.id,
    name: d.name,
    model: d.status?.os ?? d.platform,
    platform: platformOf(d.platform),
    coverage: coverageOf(d.coverage),
    coverageNote: d.status?.coverage_note ?? (d.coverage ? `Reported: ${d.coverage}` : "No coverage reported"),
    lastSeen: d.last_seen_at,
    revision: d.last_revision,
    revisionState: latest ? (latest.state as RevisionState) : null,
    capabilities: caps,
    telemetryGaps: d.telemetry_gaps,
    awaitingRetarget: d.awaiting_retarget === true,
    blockedToday: 0,
    flowsToday: 0,
  };
}

export function mapIncident(i: WireIncident): Incident {
  const t = i.facts?.transfer;
  const measurement = t && (t.bytes_out !== undefined || t.bytes_in !== undefined) ? `${t.bytes_out ?? 0} B out · ${t.bytes_in ?? 0} B in${t.source ? ` (${t.source})` : ""}` : "No transfer measurement reported for this attempt.";
  return {
    id: i.id,
    revision: i.revision,
    kind: i.kind,
    urgency: i.urgency,
    state: i.state,
    deviceId: i.device_id,
    sessionId: i.session_id ?? undefined,
    app: i.app ?? undefined,
    chain: i.facts?.chain ? i.facts.chain.map((n) => ({ name: String(n), exe: String(n) })) : undefined,
    chainComplete: i.facts?.chain ? false : undefined,
    destination: i.destination,
    port: i.port ?? undefined,
    protocol: i.transport && i.port ? `${i.transport.toUpperCase()} ${i.port}` : undefined,
    rule: i.rule ?? undefined,
    policyRevision: i.policy_revision ?? undefined,
    reason: i.reason,
    explanation: i.reason,
    measurement,
    facts: [
      ...(i.rule ? [{ label: "Rule", value: i.rule, source: "endpoint decision" }] : []),
      ...(i.process_instance ? [{ label: "Process instance", value: i.process_instance, source: "endpoint" }] : []),
      { label: "Incident revision", value: String(i.revision) },
    ],
    occurrences: i.occurrences,
    firstAt: i.first_at,
    lastAt: i.last_at,
  };
}

export function mapRevision(r: WireRevision): Revision {
  const byDevice = new Map<string, Revision["devices"][number]>();
  for (const x of r.devices) {
    const e = byDevice.get(x.device_id) ?? { deviceId: x.device_id, states: [] };
    e.states.push({ state: x.state as RevisionState, at: x.at, detail: x.detail ?? undefined });
    byDevice.set(x.device_id, e);
  }
  return {
    revision: r.revision,
    title: r.message ?? (r.rollback_of ? `Rollback to revision ${r.rollback_of}` : r.grants.length ? `Revision ${r.revision} (with ${r.grants.length} temporary grant${r.grants.length === 1 ? "" : "s"})` : `Revision ${r.revision}`),
    author: r.approved_by,
    authorizedBy: r.authorized_by ?? null,
    ownerKeyId: r.owner_key_id,
    createdAt: r.created_at,
    rollbackOf: r.rollback_of ?? undefined,
    source: `sha256 ${r.source_digest.slice(0, 12)}`,
    changes: [],
    devices: [...byDevice.values()],
    platformNotes: r.platforms
      .filter((p) => (p.report?.omitted?.length ?? 0) > 0 || (p.report?.unavailable_session_profiles?.length ?? 0) > 0)
      .map((p) => ({ platform: p.platform, note: [p.report?.omitted?.length ? `${p.report.omitted.length} rule(s) left out with report` : "", p.report?.unavailable_session_profiles?.length ? `session profiles unavailable: ${p.report.unavailable_session_profiles.join(", ")}` : ""].filter(Boolean).join("; ") })),
  };
}

function parseIntent(s: string | null): string | undefined {
  if (!s) return undefined;
  try {
    return String((JSON.parse(s) as { text?: unknown }).text ?? "");
  } catch {
    return undefined;
  }
}

export function mapSession(s: WireSession): Session {
  return { id: s.id, deviceId: s.device_id, profile: s.profile, boundary: s.boundary === "linux_cgroup" ? "Linux cgroup v2 + nftables" : s.boundary, boundaryKind: s.boundary === "linux_cgroup" ? "linux_cgroup" : "instrumented_only", verified: !!s.verified, state: s.state === "running" ? "running" : "ended", startedAt: s.started_at, endedAt: s.ended_at ?? undefined, closeRequestedAt: s.close_requested_at ?? undefined, launcher: "moat-launch", chain: [], intent: parseIntent(s.intent), allowed: [], blocked: [], grants: [] };
}

/** Live apps: executable identities from recorded flows. Nothing is labeled "enforced" from a name; counts are evidence. */
export function mapApp(a: WireApp): App {
  return {
    id: a.id,
    name: a.name,
    family: a.family ?? "",
    exe: a.exe ?? "executable not recorded",
    signing: a.signer ?? (a.identity === "unknown" ? "identity unknown" : "no signing identity reported"),
    devices: a.devices,
    profile: "",
    enforcement: "evidence",
    identity: a.identity,
    counts: { flows: a.flows, denied: a.denied, observed: a.observed, sessions: a.sessions },
    destinations: a.destinations.slice(0, 12).map((d) => ({ host: d.port ? `${d.host}:${d.port}` : d.host, count: d.count, verdict: d.verdict, firstSeen: d.new })),
    category: a.identity === "unknown" ? "Identity unknown" : a.family ?? "app",
    lastActive: a.lastActive,
  };
}

export function grantScope(g: Pick<WireGrant, "device_id" | "session_id" | "process_instance" | "transport" | "port">): string {
  const who = g.session_id ? `session ${g.session_id}` : g.process_instance ? `app ${g.process_instance}` : "unscoped";
  return `${who}${g.device_id ? ` on ${g.device_id}` : ""} · ${g.transport.toUpperCase()} ${g.port ?? "any"}`;
}

export async function loadLive(api: Api, now = () => new Date()): Promise<Snapshot> {
  const since = new Date(now().getTime() - 24 * 3600_000).toISOString();
  const [me, overview, devices, incidents, revisions, sessions, grants, rollups, apps] = await Promise.all([
    api.get<WireMe>("/v1/me"),
    api.get<WireOverview>("/v1/overview"),
    api.get<WireDevice[]>("/v1/devices"),
    api.get<WireIncident[]>("/v1/incidents"),
    api.get<WireRevision[]>("/v1/policy/revisions"),
    api.get<WireSession[]>("/v1/sessions"),
    api.get<WireGrant[]>("/v1/grants"),
    api.get<WireRollup[]>(`/v1/rollups?since=${encodeURIComponent(since)}`),
    api.get<WireApp[]>("/v1/apps"),
  ]);
  const hours = new Map<string, { hour: string; allowed: number; blocked: number; observed: number }>();
  for (const r of rollups) {
    const h = hours.get(r.hour) ?? { hour: r.hour, allowed: 0, blocked: 0, observed: 0 };
    if (r.verdict === "deny") h.blocked += r.flows;
    else if (r.verdict === "allow") h.allowed += r.flows;
    else if (r.verdict === "observed") h.observed += r.flows;
    hours.set(r.hour, h);
  }
  const fetchedAt = now().toISOString();
  return {
    generatedAt: overview.server_time,
    serverTime: overview.server_time,
    fetchedAt,
    demo: false,
    viewer: { name: me.name, role: me.role },
    policyRevision: overview.revision ?? 0,
    devices: devices.map(mapDevice),
    incidents: incidents.map(mapIncident),
    revisions: revisions.map(mapRevision),
    sessions: sessions.map(mapSession),
    apps: apps.map(mapApp),
    timeline: [...hours.values()].sort((a, b) => a.hour.localeCompare(b.hour)),
    grants: grants.filter((g) => g.state === "active").map((g) => ({ id: g.id, destination: `${g.destination}${g.port ? `:${g.port}` : ""}`, scope: grantScope(g), expiresAt: g.expires_at, by: g.created_by, state: g.state })),
    simulation: null,
  };
}
