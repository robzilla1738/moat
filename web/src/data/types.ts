export type Coverage = "protected-session" | "enforced" | "monitoring" | "dns-only" | "degraded" | "isolated" | "unknown";
export type Support = "supported" | "partial" | "untested" | "unsupported";
export type Platform = "macos" | "linux" | "ios" | "android-tv";
export type RevisionState = "approved" | "distributed" | "received" | "applied" | "verified" | "rejected" | "trial" | "confirmed" | "rolled_back";

export interface Capability { key: string; label: string; support: Support; note?: string }

export interface Device {
  id: string;
  name: string;
  model: string;
  platform: Platform;
  coverage: Coverage;
  coverageNote: string;
  /** Last report time on the controller's clock; null when the device never reported. */
  lastSeen: string | null;
  revision: number | null;
  revisionState: RevisionState | null;
  capabilities: Capability[];
  telemetryGaps: [number, number][];
  isController?: boolean;
  blockedToday: number;
  flowsToday: number;
}

export interface ChainNode { name: string; exe: string; pid?: number; signed?: string; note?: string }

export interface Incident {
  id: string;
  revision: number;
  kind: "blocked_connection" | "coverage_lost" | "telemetry_gap" | "policy_rejected" | "policy_rolled_back" | "dns_blocked" | "new_destination";
  urgency: "low" | "medium" | "high";
  state: "open" | "acknowledged" | "resolved";
  deviceId: string;
  sessionId?: string;
  app?: string;
  chain?: ChainNode[];
  chainComplete?: boolean;
  destination: string;
  destinationLabel?: string;
  port?: number;
  protocol?: string;
  rule?: string;
  policyRevision?: number;
  reason: string;
  explanation: string;
  measurement: string;
  facts: { label: string; value: string; source?: string }[];
  occurrences: number;
  firstAt: string;
  lastAt: string;
  action?: ActionState;
}

/**
 * The state of an owner action, as far as evidence supports it. "sending" and "pending" are never shown as applied;
 * "active" needs an endpoint receipt; "simulated" exists only in demo mode.
 */
export type ActionPhase = "planning" | "review" | "sending" | "pending" | "active" | "rejected" | "failed" | "expired" | "revoked" | "done" | "simulated";

/** The exact grant the controller proposes (moat.grant.v1 plan); critical scope is rendered from this, never from prose. */
/** A `moat.grant.v1` object (contracts/schemas/moat.grant.v1.schema.json) as the controller planned it. */
export interface GrantV1 {
  schema: "moat.grant.v1";
  grant_id: string;
  idempotency_key: string;
  scope: { kind: "task"; device_id: string; boot_id: string; task_id: string } | { kind: "app_on_device"; device_id: string; executable: { path: string } };
  destination: { kind: "address"; address: string } | { kind: "hostname"; hostname: string };
  transport: string;
  port: number;
  issued_at: string;
  not_before: string;
  admission_until: string;
  stream_policy: string;
  base_policy_digest: string;
  issuer: { principal: string; role: "owner" | "delegated"; key_id?: string };
  approval_digest: string;
  reason?: string;
}
export interface GrantPlanView {
  plan_id: string;
  /** Canonical digest of `plan` (what a delegated approver signs); the browser recomputes it before signing. */
  digest: string;
  approval_expires_at: string;
  grant_id: string | null;
  kind: "allow_once" | "temporary";
  context: { schema: "moat.grant_context.v1"; kind: string; policy_revision: number; requested_by: string; incident?: { id: string; revision: number } };
  plan: GrantV1;
}
export interface ActionState {
  kind: "allow_once" | "keep_blocked" | "acknowledge";
  phase: ActionPhase;
  steps: { label: string; state: "done" | "active" | "pending" | "failed"; at?: string; detail?: string }[];
  grantId?: string;
  plan?: GrantPlanView;
  revision?: number;
  authorizedBy?: string | null;
  expiresAt?: string;
  error?: string;
}

export interface Session {
  id: string;
  deviceId: string;
  profile: string;
  boundary: string;
  boundaryKind: "linux_cgroup" | "instrumented_only" | "external_runtime";
  verified: boolean;
  state: "running" | "ended";
  closeRequestedAt?: string;
  startedAt: string;
  endedAt?: string;
  launcher: string;
  chain: ChainNode[];
  intent?: string;
  allowed: { destination: string; count: number; via: string }[];
  blocked: { destination: string; count: number; rule: string }[];
  grants: { destination: string; expiresAt: string }[];
}

export interface App {
  id: string;
  name: string;
  family: string;
  exe: string;
  signing: string;
  devices: string[];
  profile: string;
  enforcement: "observed" | "enforced" | "session-only";
  destinations: { host: string; count: number; verdict: "allow" | "deny" | "observed"; firstSeen?: boolean }[];
  category: string;
  recognizedBy?: string;
  lastActive: string;
}

export interface RevisionDevice { deviceId: string; states: { state: RevisionState; at: string; detail?: string }[] }

export interface Revision {
  revision: number;
  title: string;
  author: string;
  /** From the signer's recorded answer; null when the controller did not record it (older revisions). */
  authorizedBy: "owner_key" | "narrowing" | "temporary_grant_overlay" | "delegated_issuer" | null;
  ownerKeyId?: string | null;
  createdAt: string;
  rollbackOf?: number;
  source: string;
  changes: { kind: "added" | "removed" | "changed"; rule: string; detail: string; broadening: boolean }[];
  devices: RevisionDevice[];
  platformNotes: { platform: string; note: string }[];
}

export interface Simulation {
  title: string;
  observations: number;
  newlyBlocked: number;
  newlyAllowed: number;
  affectedApps: { app: string; flows: number }[];
  changed: { device: string; app: string; destination: string; before: string; after: string }[];
  unobserved: string[];
  platforms: { adapter: string; compiles: boolean; omitted: string[]; note?: string }[];
  unacknowledged: string[];
  disclaimer: string;
}

export interface TimelinePoint { hour: string; allowed: number; blocked: number; observed: number }

export interface Snapshot {
  generatedAt: string;
  demo: boolean;
  /** Controller clock at the time of the snapshot (demo: the browser clock). Freshness is computed from it. */
  serverTime: string;
  /** Browser clock when the snapshot was received. */
  fetchedAt: string;
  viewer?: { name: string; role: "owner" | "viewer" | "launcher" | "agent" };
  policyRevision: number;
  devices: Device[];
  incidents: Incident[];
  sessions: Session[];
  apps: App[];
  revisions: Revision[];
  simulation: Simulation | null;
  timeline: TimelinePoint[];
  grants: { id: string; destination: string; scope: string; expiresAt: string; by: string; state?: string }[];
}
