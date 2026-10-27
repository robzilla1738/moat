/**
 * W14 learning and workflow packs: wire types for the controller's review surfaces (`GET /v1/learning`,
 * `GET /v1/learning/candidates/:id`, `GET /v1/packs`, `GET /v1/packs/:id/delta`) and the fixed sample shown in demo
 * mode. Learning produces a proposal, never trust: nothing here is accepted or allowed by being listed.
 */
export interface LearningEntry { destination: string; port: number | null; transport: string | null; occurrences: number; first_at: string; last_at: string; verdicts: string[]; status: "proposed" }
export interface DiffRow { index: number; destination: string; port: number | null; transport: string | null; occurrences: number; change: "adds" | "in_baseline"; unknown_destination: boolean; denied_only: boolean }
export interface PermissionDiff { baseline_id: string | null; adds: number; rows: DiffRow[]; removals: { destination: string; port: number | null; caveat: string }[]; note: string }
export interface Candidate {
  id: string;
  capture_id: string | null;
  baseline_id: string | null;
  kind: "capture" | "drift" | "import";
  device_id: string;
  exe: string;
  signer: string | null;
  entries: LearningEntry[];
  completeness: "complete" | "incomplete";
  incomplete_reasons: string[];
  identity_changes: { exe: string; signer: string | null; first_at: string }[];
  removal_proposals: { destination: string; port: number | null; caveat: string }[];
  source: string | null;
  assumptions: Record<string, unknown> | null;
  created_at: string;
  status: "open" | "reviewed" | "discarded";
  note: string;
  permission_diff: PermissionDiff;
}
export interface Capture { id: string; device_id: string; exe: string; signer: string | null; workflow: string; network_context: string; started_at: string; ends_at: string; max_records: number; state: "capturing" | "window_ended" | "closed"; candidate_id: string | null }
export interface Baseline { id: string; candidate_id: string; device_id: string; exe: string; signer: string | null; workflow: string | null; network_context: string | null; entries: LearningEntry[]; digest: string; completeness: string; source: string | null; assumptions: Record<string, unknown> | null; approved_by: string; approved_at: string; supersedes: string | null; retired: { retired_at: string; reason: string } | null }
export interface LearningOverview { captures: Capture[]; review_queue: Candidate[]; drift_queue: Candidate[]; reviewed: Candidate[]; baselines: Baseline[]; limits: { max_capture_hours: number; max_capture_records: number; unused_removal_days: number } }

export type CellSupport = "supported" | "untested" | "unsupported" | "unknown";
export interface PackCell { device_id: string; device: string; platform: string; support: CellSupport; missing: { capability: string; support: CellSupport }[]; takes_effect: boolean }
export interface PackModuleDelta { id: string; name: string; optional: boolean; rationale: string; required_capabilities: string[]; enabled: boolean; destinations: { hosts: string[]; cidrs: string[]; ports: number[]; transport: string | null }; newly_allowed: string[]; expected_breakage_if_omitted: string; provenance: string; compatible_versions: Record<string, string>; test_recipe: string[]; cells: PackCell[]; unsupported_cells: number }
export interface PackDelta { pack: { id: string; version: string; name: string; description: string; profile: string }; revision: number | null; problems: string[]; devices: { id: string; name: string; platform: string }[]; modules: PackModuleDelta[]; effective: { modules_to_enable: number; newly_allowed: string[]; unsupported_cells: number }; note: string }
export interface PackSummary { id: string; version: string; name: string; description: string; profile: string; modules: { id: string; name: string; optional: boolean }[]; problems: string[] }

/** One gap reason per line; unknown identity and lost events are the ones that block a "complete" claim. */
export function gapKind(reason: string): "identity" | "lost" | "pending" | "budget" | "import" | "family" | "other" {
  if (/no executable identity/.test(reason)) return "identity";
  if (/lost/.test(reason)) return "lost";
  if (/not all arrived/.test(reason)) return "pending";
  if (/record budget/.test(reason)) return "budget";
  if (/imported/.test(reason)) return "import";
  if (/other identities/.test(reason)) return "family";
  return "other";
}

/** The accept request a reviewer's selection becomes. Nothing is accepted by default; an incomplete candidate needs
 * an explicit acknowledgement. Returns the refusal to show instead of a body when the selection cannot be sent. */
export function acceptBody(c: Pick<Candidate, "completeness" | "entries">, selected: number[], acknowledged: boolean): { accept: number[]; acknowledge_incomplete: boolean } | { refusal: string } {
  const accept = [...new Set(selected)].filter((i) => Number.isInteger(i) && i >= 0 && i < c.entries.length).sort((a, b) => a - b);
  if (!accept.length) return { refusal: "Select the entries you reviewed and want. Nothing is accepted by default." };
  if (c.completeness === "incomplete" && !acknowledged) return { refusal: "The evidence is incomplete. Acknowledge the gaps to accept a partial baseline." };
  return { accept, acknowledge_incomplete: c.completeness === "incomplete" && acknowledged };
}

export const SUPPORT_TONE: Record<CellSupport, string> = { supported: "green", untested: "amber", unsupported: "red", unknown: "neutral" };

// ------------------------------------------------------------------------------------------------ demo sample

const t = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
const e = (destination: string, port: number, occurrences: number, verdicts: string[], minutesAgo = 30): LearningEntry => ({ destination, port, transport: "tcp", occurrences, first_at: t(minutesAgo + 20), last_at: t(minutesAgo), verdicts, status: "proposed" });

const npmEntries = [e("registry.npmjs.org", 443, 412, ["allow"]), e("unknown", 443, 3, ["observed"]), e("oss-cn-beijing.aliyuncs.com", 443, 1, ["deny"]), e("objects.githubusercontent.com", 443, 18, ["observed"])];
const driftEntries = [e("api.anthropic.com", 443, 64, ["allow"], 10), e("statsig.anthropic.com", 443, 9, ["observed"], 12)];

export const demoLearning: LearningOverview = {
  captures: [
    { id: "cap-demo-1", device_id: "omarchy", exe: "/usr/bin/npm", signer: null, workflow: "npm install", network_context: "home LAN", started_at: t(50), ends_at: t(-10), max_records: 5000, state: "capturing", candidate_id: null },
    { id: "cap-demo-0", device_id: "omarchy", exe: "/usr/bin/node", signer: null, workflow: "dependency install (lockfile)", network_context: "home LAN", started_at: t(240), ends_at: t(180), max_records: 5000, state: "closed", candidate_id: "cand-demo-1" },
  ],
  review_queue: [
    {
      id: "cand-demo-1",
      capture_id: "cap-demo-0",
      baseline_id: null,
      kind: "capture",
      device_id: "omarchy",
      exe: "/usr/bin/node",
      signer: null,
      entries: npmEntries,
      completeness: "incomplete",
      incomplete_reasons: ["3 connection(s) in the window had no executable identity and cannot be attributed", "events 1204–1211 were lost on or before delivery"],
      identity_changes: [],
      removal_proposals: [],
      source: null,
      assumptions: null,
      created_at: t(180),
      status: "open",
      note: "Every entry is proposed. Occurring during capture, or occurring often, does not make it trusted.",
      permission_diff: {
        baseline_id: null,
        adds: 4,
        rows: npmEntries.map((x, index) => ({ index, destination: x.destination, port: x.port, transport: x.transport, occurrences: x.occurrences, change: "adds", unknown_destination: x.destination === "unknown", denied_only: x.verdicts.length === 1 && x.verdicts[0] === "deny" })),
        removals: [],
        note: "Accepting an entry adds an exact allow for this identity once you enforce the baseline with your owner key. Denies keep precedence.",
      },
    },
  ],
  drift_queue: [
    {
      id: "cand-demo-2",
      capture_id: null,
      baseline_id: "base-demo-1",
      kind: "drift",
      device_id: "omarchy",
      exe: "/home/rob/.local/bin/claude",
      signer: null,
      entries: driftEntries,
      completeness: "complete",
      incomplete_reasons: [],
      identity_changes: [{ exe: "/home/rob/.local/share/claude/versions/2.1.0/claude", signer: null, first_at: t(90) }],
      removal_proposals: [{ destination: "sentry.io", port: 443, caveat: "unused for 30+ days; seasonal or rare workflows (yearly tax software, travel) may still need it" }],
      source: null,
      assumptions: null,
      created_at: t(8),
      status: "open",
      note: "Every entry is proposed. Occurring during capture, or occurring often, does not make it trusted.",
      permission_diff: {
        baseline_id: "base-demo-1",
        adds: 2,
        rows: driftEntries.map((x, index) => ({ index, destination: x.destination, port: x.port, transport: x.transport, occurrences: x.occurrences, change: "adds", unknown_destination: false, denied_only: false })),
        removals: [{ destination: "sentry.io", port: 443, caveat: "unused for 30+ days; seasonal or rare workflows (yearly tax software, travel) may still need it" }],
        note: "Accepting an entry adds an exact allow for this identity once you enforce the baseline with your owner key. Denies keep precedence.",
      },
    },
  ],
  reviewed: [],
  baselines: [
    { id: "base-demo-1", candidate_id: "cand-demo-0", device_id: "omarchy", exe: "/home/rob/.local/bin/claude", signer: null, workflow: "coding session", network_context: "home LAN", entries: [e("api.github.com", 443, 120, ["allow"], 60 * 24 * 40), e("sentry.io", 443, 4, ["allow"], 60 * 24 * 40)], digest: "sha256:4f2a9c0e7d51b8a3", completeness: "complete", source: null, assumptions: null, approved_by: "owner", approved_at: t(60 * 24 * 40), supersedes: null, retired: null },
  ],
  limits: { max_capture_hours: 8, max_capture_records: 20000, unused_removal_days: 30 },
};

const cell = (device_id: string, device: string, platform: string, support: CellSupport, missing: [string, CellSupport][]): PackCell => ({ device_id, device, platform, support, missing: missing.map(([capability, s]) => ({ capability, support: s })), takes_effect: support === "supported" });

export const demoPacks: PackDelta[] = [
  {
    pack: { id: "coding", version: "2026.10.1", name: "Basic coding", description: "Repository access, package acquisition and the selected model API as separate modules for a protected coding session.", profile: "coding-session" },
    revision: 14,
    problems: [],
    devices: [
      { id: "omarchy", name: "Omarchy", platform: "linux" },
      { id: "mbp", name: "MacBook Pro", platform: "macos" },
    ],
    modules: [
      { id: "repository", name: "Repository access (GitHub)", optional: false, rationale: "git fetch/push and the GitHub API over HTTPS. An allowed API can also write data.", required_capabilities: ["session_enforcement", "session_hostname_proxy"], enabled: true, destinations: { hosts: ["github.com", "api.github.com", "codeload.github.com"], cidrs: [], ports: [443], transport: "tcp" }, newly_allowed: [], expected_breakage_if_omitted: "git clone/fetch/push and gh fail inside the session.", provenance: "packs/services/github.json@2026.10.1", compatible_versions: { git: ">=2.30", gh: ">=2.0" }, test_recipe: [], cells: [cell("omarchy", "Omarchy", "linux", "untested", [["session_hostname_proxy", "untested"]]), cell("mbp", "MacBook Pro", "macos", "unsupported", [["session_enforcement", "unsupported"], ["session_hostname_proxy", "unsupported"]])], unsupported_cells: 2 },
      { id: "packages", name: "Package acquisition (npm)", optional: false, rationale: "Dependency downloads. Download and publish share registry.npmjs.org; publication is not separately enforced.", required_capabilities: ["session_enforcement", "session_hostname_proxy"], enabled: false, destinations: { hosts: ["registry.npmjs.org"], cidrs: [], ports: [443], transport: "tcp" }, newly_allowed: ["registry.npmjs.org"], expected_breakage_if_omitted: "npm install fails inside the session; lockfile installs too.", provenance: "packs/services/npm.json@2026.10.1", compatible_versions: { npm: ">=9" }, test_recipe: [], cells: [cell("omarchy", "Omarchy", "linux", "untested", [["session_hostname_proxy", "untested"]]), cell("mbp", "MacBook Pro", "macos", "unsupported", [["session_enforcement", "unsupported"], ["session_hostname_proxy", "unsupported"]])], unsupported_cells: 2 },
      { id: "model-api", name: "Selected model API (Anthropic)", optional: true, rationale: "The model API the agent uses. Separate from repository and packages so it can be dropped for offline work.", required_capabilities: ["session_enforcement", "session_hostname_proxy"], enabled: false, destinations: { hosts: ["api.anthropic.com"], cidrs: [], ports: [443], transport: "tcp" }, newly_allowed: ["api.anthropic.com"], expected_breakage_if_omitted: "the coding agent cannot reach its model.", provenance: "packs/services/anthropic.json@2026.10.1", compatible_versions: { "claude-code": ">=1.0" }, test_recipe: [], cells: [cell("omarchy", "Omarchy", "linux", "untested", [["session_hostname_proxy", "untested"]]), cell("mbp", "MacBook Pro", "macos", "unsupported", [["session_enforcement", "unsupported"], ["session_hostname_proxy", "unsupported"]])], unsupported_cells: 2 },
    ],
    effective: { modules_to_enable: 2, newly_allowed: ["registry.npmjs.org", "api.anthropic.com"], unsupported_cells: 6 },
    note: "The delta is computed from the pack's rule material and the devices' advertised capabilities. Enabling modules is an owner-authorized broadening proposal; replay of recorded traffic is an estimate.",
  },
];
