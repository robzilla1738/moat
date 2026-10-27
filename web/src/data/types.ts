export type Coverage = "protected-session" | "enforced" | "monitoring" | "dns-only" | "degraded" | "isolated";
export type Support = "supported" | "partial" | "untested" | "unsupported";
export type Platform = "macos" | "linux" | "ios" | "android-tv";
export type RevisionState = "approved" | "distributed" | "received" | "applied" | "verified" | "rejected";

export interface Capability { key: string; label: string; support: Support; note?: string }

export interface Device {
  id: string;
  name: string;
  model: string;
  platform: Platform;
  coverage: Coverage;
  coverageNote: string;
  lastSeen: string; // ISO
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

export interface ActionState {
  kind: "allow_once" | "keep_blocked";
  steps: { label: string; state: "done" | "active" | "pending" | "failed"; at?: string; detail?: string }[];
  expiresAt?: string;
}

export interface Session {
  id: string;
  deviceId: string;
  profile: string;
  boundary: string;
  boundaryKind: "linux_cgroup" | "instrumented_only" | "external_runtime";
  verified: boolean;
  state: "running" | "ended";
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
  authorizedBy: "owner_key" | "narrowing" | "temporary_grant_overlay";
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
  policyRevision: number;
  devices: Device[];
  incidents: Incident[];
  sessions: Session[];
  apps: App[];
  revisions: Revision[];
  simulation: Simulation;
  timeline: TimelinePoint[];
  grants: { id: string; destination: string; scope: string; expiresAt: string; by: string }[];
}
