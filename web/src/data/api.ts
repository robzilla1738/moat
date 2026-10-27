/**
 * Live mode: when the UI is served by a Moat controller and an owner/viewer token is stored, read the controller's
 * API and map it onto the UI model. Anything the controller does not provide stays empty rather than invented.
 */
import type { Coverage, Device, Incident, Revision, Session, Snapshot } from "./types";
import { demo } from "./demo";

const TOKEN_KEY = "moat.token";

async function get<T>(path: string, token: string): Promise<T> {
  const r = await fetch(path, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

const coverageOf = (c: string | null): Coverage => (c === "protected-session" ? "protected-session" : c === "emergency-isolation" ? "isolated" : c === "degraded" ? "degraded" : c === "enforced" ? "enforced" : "monitoring");

export async function loadLive(): Promise<Snapshot | null> {
  const token = typeof localStorage !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
  if (!token) return null;
  try {
    const [overview, devices, incidents, revisions, sessions] = await Promise.all([
      get<{ revision: number | null }>("/v1/overview", token),
      get<{ id: string; name: string; platform: string; coverage: string | null; last_seen_at: string | null; last_revision: number | null; telemetry_gaps: [number, number][] }[]>("/v1/devices", token),
      get<{ id: string; revision: number; kind: Incident["kind"]; urgency: Incident["urgency"]; state: Incident["state"]; device_id: string; session_id: string | null; app: string | null; destination: string; port: number | null; reason: string; rule: string | null; policy_revision: number | null; occurrences: number; first_at: string; last_at: string }[]>("/v1/incidents", token),
      get<{ revision: number; created_at: string; approved_by: string; rollback_of: number | null; devices: { device_id: string; state: string; at: string }[] }[]>("/v1/policy/revisions", token),
      get<{ id: string; device_id: string; profile: string; boundary: string; verified: number; state: string; started_at: string; ended_at: string | null; intent: string | null }[]>("/v1/sessions", token),
    ]);
    const devs: Device[] = devices.map((d) => ({ id: d.id, name: d.name, model: d.platform, platform: d.platform === "macos" ? "macos" : "linux", coverage: coverageOf(d.coverage), coverageNote: d.coverage ?? "unknown", lastSeen: d.last_seen_at ?? new Date(0).toISOString(), revision: d.last_revision, revisionState: null, capabilities: [], telemetryGaps: d.telemetry_gaps, blockedToday: 0, flowsToday: 0 }));
    const incs: Incident[] = incidents.map((i) => ({ id: i.id, revision: i.revision, kind: i.kind, urgency: i.urgency, state: i.state, deviceId: i.device_id, sessionId: i.session_id ?? undefined, app: i.app ?? undefined, destination: i.destination, port: i.port ?? undefined, rule: i.rule ?? undefined, policyRevision: i.policy_revision ?? undefined, reason: i.reason, explanation: i.reason, measurement: "", facts: [], occurrences: i.occurrences, firstAt: i.first_at, lastAt: i.last_at }));
    const revs: Revision[] = revisions.map((r) => ({ revision: r.revision, title: r.rollback_of ? `Rollback to revision ${r.rollback_of}` : `Revision ${r.revision}`, author: r.approved_by, authorizedBy: "owner_key", createdAt: r.created_at, rollbackOf: r.rollback_of ?? undefined, source: "", changes: [], devices: Object.values(r.devices.reduce<Record<string, { deviceId: string; states: { state: never; at: string }[] }>>((acc, x) => ((acc[x.device_id] ??= { deviceId: x.device_id, states: [] }).states.push({ state: x.state as never, at: x.at }), acc), {})), platformNotes: [] }));
    const sess: Session[] = sessions.map((s) => ({ id: s.id, deviceId: s.device_id, profile: s.profile, boundary: s.boundary === "linux_cgroup" ? "Linux cgroup v2 + nftables" : s.boundary, boundaryKind: s.boundary === "linux_cgroup" ? "linux_cgroup" : "instrumented_only", verified: !!s.verified, state: s.state === "running" ? "running" : "ended", startedAt: s.started_at, endedAt: s.ended_at ?? undefined, launcher: "moat-launch", chain: [], intent: s.intent ? (JSON.parse(s.intent) as { text: string }).text : undefined, allowed: [], blocked: [], grants: [] }));
    return { ...demo, demo: false, generatedAt: new Date().toISOString(), policyRevision: overview.revision ?? 0, devices: devs, incidents: incs, revisions: revs, sessions: sess, apps: [], timeline: [], grants: [] };
  } catch {
    return null;
  }
}
