/**
 * W12 standalone daily firewall: the read models behind the Apps-first UI, the app detail, "What changed?" and local
 * diagnostics. Everything here is derived from recorded evidence (flow store, revisions, grants, device reports) and
 * from the Rust core through `moatctl` (normalize / explain). Nothing is inferred from names or timing alone:
 *
 *  - An app is an executable identity (path + signer when reported). A family label without an executable is shown as
 *    "identity unknown" and never merged into a known app.
 *  - "Why the current rules apply" is the core's deterministic explanation of a recorded attempt against the policy in
 *    force now, shown next to what the endpoint actually decided at the time (they can differ; both are facts).
 *  - "What changed?" separates directly observed differences between two intervals from possible explanations, and
 *    links each candidate to a reversible, owner-reviewed test. It never claims causation.
 */
import { createHash } from "node:crypto";
import type { Controller } from "./controller.ts";

export const UNKNOWN_APP = "unknown-identity";

/** Stable opaque id for an executable identity on any device. */
export function appId(exe: string | null, signer: string | null): string {
  if (!exe) return UNKNOWN_APP;
  return "app-" + createHash("sha256").update(`${exe}\n${signer ?? ""}`).digest("hex").slice(0, 16);
}

interface FlowRow { id: number; device_id: string; seq: number; at: string; kind: string; app: string | null; session_id: string | null; process_instance: string | null; destination: string | null; port: number | null; transport: string | null; verdict: string | null; observed: number; rule: string | null; policy_revision: number | null; attempt: string | null; exe: string | null; signer: string | null; detail: string | null }

export interface AppSummary {
  id: string;
  name: string;
  family: string | null;
  exe: string | null;
  signer: string | null;
  identity: "executable" | "unknown";
  devices: string[];
  sessions: number;
  flows: number;
  denied: number;
  observed: number;
  destinations: { host: string; port: number | null; count: number; verdict: "allow" | "deny" | "observed"; firstAt: string; lastAt: string; new: boolean }[];
  lastActive: string;
  firstSeen: string;
}

const WINDOW_DAYS = 7;
const NEW_DESTINATION_MS = 24 * 3600_000;

function baseName(p: string) {
  return p.split("/").filter(Boolean).pop() ?? p;
}

function verdictOf(r: Pick<FlowRow, "verdict" | "observed">): "allow" | "deny" | "observed" {
  if (r.verdict === "deny") return "deny";
  return r.observed ? "observed" : "allow";
}

/** Apps seen in the last week, by executable identity. Unknown identity is its own row and is never hidden. */
export function apps(c: Controller, opts: { deviceId?: string; now?: Date } = {}): AppSummary[] {
  const now = opts.now ?? c.now();
  const since = new Date(now.getTime() - WINDOW_DAYS * 86400_000).toISOString();
  const rows = c.flows.db
    .prepare(`SELECT device_id, app, exe, signer, session_id, destination, port, verdict, observed, MIN(at) AS first_at, MAX(at) AS last_at, COUNT(*) AS n
              FROM flows WHERE kind = 'flow' AND at >= ? ${opts.deviceId ? "AND device_id = ?" : ""}
              GROUP BY device_id, app, exe, signer, session_id IS NOT NULL, destination, port, verdict, observed`)
    .all(...(opts.deviceId ? [since, opts.deviceId] : [since])) as unknown as { device_id: string; app: string | null; exe: string | null; signer: string | null; session_id: string | null; destination: string | null; port: number | null; verdict: string | null; observed: number; first_at: string; last_at: string; n: number }[];
  const byId = new Map<string, AppSummary>();
  for (const r of rows) {
    const id = appId(r.exe, r.signer);
    let a = byId.get(id);
    if (!a) {
      a = { id, name: r.exe ? baseName(r.exe) : "Identity unknown", family: r.exe ? r.app : null, exe: r.exe, signer: r.signer, identity: r.exe ? "executable" : "unknown", devices: [], sessions: 0, flows: 0, denied: 0, observed: 0, destinations: [], lastActive: r.last_at, firstSeen: r.first_at };
      byId.set(id, a);
    }
    if (!a.devices.includes(r.device_id)) a.devices.push(r.device_id);
    if (r.session_id) a.sessions += r.n;
    a.flows += r.n;
    const v = verdictOf(r);
    if (v === "deny") a.denied += r.n;
    if (v === "observed") a.observed += r.n;
    if (r.last_at > a.lastActive) a.lastActive = r.last_at;
    if (r.first_at < a.firstSeen) a.firstSeen = r.first_at;
    const host = r.destination ?? "unknown";
    const d = a.destinations.find((x) => x.host === host && x.port === r.port && x.verdict === v);
    if (d) {
      d.count += r.n;
      if (r.first_at < d.firstAt) d.firstAt = r.first_at;
      if (r.last_at > d.lastAt) d.lastAt = r.last_at;
    } else a.destinations.push({ host, port: r.port, count: r.n, verdict: v, firstAt: r.first_at, lastAt: r.last_at, new: false });
  }
  for (const a of byId.values()) {
    for (const d of a.destinations) {
      // "new" = first seen in the last day AND the app itself existed before that (an app seen for the first time
      // today has no history to compare against; everything would be "new").
      d.new = now.getTime() - Date.parse(d.firstAt) < NEW_DESTINATION_MS && Date.parse(a.firstSeen) < Date.parse(d.firstAt) - 1;
    }
    a.destinations.sort((x, y) => y.count - x.count);
    a.devices.sort();
  }
  return [...byId.values()].sort((x, y) => (x.identity === "unknown" ? 1 : 0) - (y.identity === "unknown" ? 1 : 0) || y.lastActive.localeCompare(x.lastActive));
}

interface NormalizedRule { id: string; action: string; layer: string; description?: string; selector: { apps?: { family?: string; executable?: string; team_id?: string; signing_id?: string }[]; devices?: string[]; device_groups?: string[]; session?: unknown; processes?: unknown[] }; destinations: unknown; transport?: string; expires_at?: string }

/** Does a rule's selector name this executable identity? (Exact path or `*\/basename` matcher; family alone also
 * counts because the core matches on it, and the UI must show every rule that can apply.) */
function ruleNamesApp(r: NormalizedRule, exe: string | null, family: string | null, inSessions: boolean): "direct" | "inherited" | null {
  const s = r.selector ?? {};
  // A session-only rule applies to this app only when it ran inside a protected session.
  if (s.session && !(s.apps?.length) && !(s.processes?.length)) return inSessions ? "inherited" : null;
  const scoped = (s.apps?.length ?? 0) > 0 || !!s.session || (s.processes?.length ?? 0) > 0;
  if (!scoped) return "inherited";
  for (const m of s.apps ?? []) {
    if (m.executable && exe && (m.executable === exe || (m.executable.startsWith("*/") && baseName(exe) === m.executable.slice(2)))) return "direct";
    if (m.family && family && m.family === family) return "direct";
  }
  return null;
}

async function rulesFor(c: Controller, source: string, exe: string | null, family: string | null, inSessions = false) {
  const norm = (await c.moatctl.normalize(source)) as { rules?: NormalizedRule[] };
  return (norm.rules ?? []).map((r) => ({ r, how: ruleNamesApp(r, exe, family, inSessions) })).filter((x) => x.how) as { r: NormalizedRule; how: "direct" | "inherited" }[];
}

/** App detail: current permissions, recent changes, activity, and why the current rules apply. */
export async function appDetail(c: Controller, id: string, opts: { now?: Date } = {}) {
  const summary = apps(c, { now: opts.now }).find((a) => a.id === id);
  if (!summary) return null;
  const cur = c.currentRevision();
  const exeClause = summary.exe ? "exe = ? AND IFNULL(signer, '') = ?" : "exe IS NULL";
  const exeArgs = summary.exe ? [summary.exe, summary.signer ?? ""] : [];
  const recent = c.flows.db.prepare(`SELECT * FROM flows WHERE kind = 'flow' AND ${exeClause} ORDER BY at DESC, id DESC LIMIT 50`).all(...exeArgs) as unknown as FlowRow[];

  // Current permissions: rules in the policy in force that name this app (direct) or apply to everything (inherited),
  // plus active temporary grants scoped to this executable. Session rules apply only inside a protected session.
  const permissions: { rule: string; action: string; layer: string; how: "direct" | "inherited" | "session" | "temporary"; description: string; expiresAt?: string; devices: { device: string; enforced: boolean; note: string | null }[] }[] = [];
  const platformOf = new Map((c.devices() as { id: string; platform: string }[]).map((d) => [d.id, d.platform]));
  if (cur && summary.exe) {
    // The owner-authorized policy, annotated per device with whether that device's compiled snapshot carries the rule.
    for (const { r, how } of await rulesFor(c, cur.source, summary.exe, summary.family, summary.sessions > 0)) {
      const devices = summary.devices.map((dv) => {
        const omitted = c.omittedOn(cur.revision, platformOf.get(dv) ?? "linux", r.id);
        return { device: dv, enforced: !omitted, note: omitted };
      });
      permissions.push({ rule: r.id, action: r.action, layer: r.layer, how: r.selector.session ? "session" : how, description: r.description ?? "", expiresAt: r.expires_at, devices });
    }
  }
  const grants = (c.grants() as { id: string; state: string; destination: string; port: number | null; transport: string; expires_at: string; grant_json?: string | null; device_id: string | null }[])
    .filter((g) => g.state === "active")
    .filter((g) => {
      try {
        const j = g.grant_json ? (JSON.parse(g.grant_json) as { scope?: { kind?: string; executable?: { path?: string } } }) : null;
        return !!summary.exe && j?.scope?.kind === "app_on_device" && j.scope.executable?.path === summary.exe;
      } catch {
        return false;
      }
    });
  for (const g of grants) permissions.push({ rule: g.id, action: "allow", layer: "temporary", how: "temporary", description: `${g.transport.toUpperCase()} ${g.destination}${g.port ? `:${g.port}` : ""} on ${g.device_id}`, expiresAt: g.expires_at, devices: g.device_id ? [{ device: g.device_id, enforced: true, note: null }] : [] });

  // Recent changes: rules naming this app that were added, removed or changed between consecutive revisions
  // (computed from the core's normalized form of each revision, newest ten).
  const revs = c.db.prepare("SELECT revision, source, created_at, approved_by FROM policy_revisions ORDER BY revision DESC LIMIT 10").all() as { revision: number; source: string; created_at: string; approved_by: string }[];
  const changes: { revision: number; at: string; by: string; kind: "added" | "removed" | "changed"; rule: string }[] = [];
  if (summary.exe) {
    const sets: Map<string, string>[] = [];
    for (const rv of revs) sets.push(new Map((await rulesFor(c, rv.source, summary.exe, summary.family, summary.sessions > 0)).map(({ r }) => [r.id, JSON.stringify(r)])));
    for (let i = 0; i + 1 < revs.length; i++) {
      const now = sets[i]!, before = sets[i + 1]!;
      for (const [k, v] of now) if (!before.has(k)) changes.push({ revision: revs[i]!.revision, at: revs[i]!.created_at, by: revs[i]!.approved_by, kind: "added", rule: k });
      else if (before.get(k) !== v) changes.push({ revision: revs[i]!.revision, at: revs[i]!.created_at, by: revs[i]!.approved_by, kind: "changed", rule: k });
      for (const k of before.keys()) if (!now.has(k)) changes.push({ revision: revs[i]!.revision, at: revs[i]!.created_at, by: revs[i]!.approved_by, kind: "removed", rule: k });
    }
  }
  // Identity changes are changes too: a new signer or executable for the same family is never inherited silently.
  const siblings = summary.family ? apps(c, { now: opts.now }).filter((a) => a.family === summary.family && a.id !== summary.id && a.identity === "executable") : [];

  // Why: the endpoint's recorded decision for the latest attempt per destination, and the core's explanation of
  // the same attempt against the policy in force now.
  const why: { destination: string; port: number | null; recorded: { verdict: string; rule: string | null; revision: number | null; at: string }; now: Record<string, unknown> | null; nowError?: string }[] = [];
  const seen = new Set<string>();
  for (const f of recent) {
    const k = `${f.destination}|${f.port}`;
    if (seen.has(k) || seen.size >= 8) continue;
    seen.add(k);
    let nowExplain: Record<string, unknown> | null = null;
    let nowError: string | undefined;
    if (cur && f.attempt) {
      try {
        // What this device's compiled policy would decide now (rules it cannot enforce are not in it).
        const policy = c.effectivePolicy(cur.revision, (platformOf.get(f.device_id) === "macos" ? "macos" : "linux")) ?? cur.source;
        nowExplain = await c.moatctl.explain(policy, JSON.parse(f.attempt));
      } catch (e) {
        nowError = (e as Error).message.slice(0, 300);
      }
    } else nowError = cur ? "the endpoint did not record a replayable attempt" : "no policy revision is in force";
    why.push({ destination: f.destination ?? "unknown", port: f.port, recorded: { verdict: verdictOf(f), rule: f.rule, revision: f.policy_revision, at: f.at }, now: nowExplain, nowError });
  }
  return {
    app: summary,
    policy_revision: cur?.revision ?? null,
    permissions,
    changes,
    identity_variants: siblings.map((s) => ({ id: s.id, exe: s.exe, signer: s.signer, firstSeen: s.firstSeen })),
    activity: recent.map((f) => ({ at: f.at, device: f.device_id, destination: f.destination, port: f.port, transport: f.transport, verdict: verdictOf(f), rule: f.rule, session: f.session_id, revision: f.policy_revision })),
    why,
    notes: [
      ...(summary.identity === "unknown" ? ["These connections were recorded without an executable identity. Rules that name an app cannot be shown to apply to them."] : []),
      ...(summary.signer ? [] : summary.exe ? ["No code-signing identity was reported for this executable; a different binary at the same path would look the same here."] : []),
    ],
  };
}

// ------------------------------------------------------------------------------------------------ What changed?

export interface Interval { from: string; to: string }

function parseInterval(s: string | null, name: string): Interval {
  const m = (s ?? "").split("/");
  if (m.length !== 2 || Number.isNaN(Date.parse(m[0]!)) || Number.isNaN(Date.parse(m[1]!)) || m[0]! >= m[1]!) throw Object.assign(new Error(`${name} must be "<ISO from>/<ISO to>" with from < to`), { status: 400 });
  return { from: new Date(m[0]!).toISOString(), to: new Date(m[1]!).toISOString() };
}

export function whatChanged(c: Controller, q: { device?: string | null; app?: string | null; working?: string | null; failing?: string | null }) {
  const working = parseInterval(q.working ?? null, "working");
  const failing = parseInterval(q.failing ?? null, "failing");
  const dev = q.device ?? null;
  const flowsIn = (iv: Interval) =>
    c.flows.db.prepare(`SELECT * FROM flows WHERE at >= ? AND at < ? ${dev ? "AND device_id = ?" : ""} ORDER BY at LIMIT 20000`).all(...(dev ? [iv.from, iv.to, dev] : [iv.from, iv.to])) as unknown as FlowRow[];
  const appFilter = (rows: FlowRow[]) => (q.app ? rows.filter((r) => r.kind !== "flow" || appId(r.exe, r.signer) === q.app || (q.app !== UNKNOWN_APP && r.app && apps(c).find((a) => a.id === q.app)?.family === r.app)) : rows);
  const A = appFilter(flowsIn(working));
  const B = appFilter(flowsIn(failing));
  const observed: { kind: string; title: string; working: string; failing: string }[] = [];
  const candidates: { kind: string; title: string; why: string; test: { label: string; action: string; reversible: true } }[] = [];

  // 1. App / executable / signer identity.
  const ids = (rows: FlowRow[]) => new Set(rows.filter((r) => r.kind === "flow").map((r) => `${r.exe ?? "unknown executable"}${r.signer ? ` (${r.signer})` : ""}`));
  const ia = ids(A), ib = ids(B);
  const newIds = [...ib].filter((x) => !ia.has(x));
  const goneIds = [...ia].filter((x) => !ib.has(x));
  if (newIds.length || goneIds.length) {
    observed.push({ kind: "identity", title: "Executable or signer identity differs", working: [...ia].join(", ") || "none recorded", failing: [...ib].join(", ") || "none recorded" });
    candidates.push({ kind: "identity", title: "The app was updated or replaced", why: `Seen only while failing: ${newIds.join(", ") || "—"}. Rules naming the old identity do not carry over automatically.`, test: { label: "Review the new identity on the app page (no trust is inherited)", action: "open_app", reversible: true } });
  }
  // 2. Policy revisions in force and grants.
  const revs = (rows: FlowRow[]) => new Set(rows.map((r) => r.policy_revision).filter((x): x is number => x !== null));
  const ra = revs(A), rb = revs(B);
  const between = c.db.prepare("SELECT revision, created_at, approved_by, rollback_of FROM policy_revisions WHERE created_at >= ? AND created_at < ? ORDER BY revision").all(working.from, failing.to) as { revision: number; created_at: string; approved_by: string; rollback_of: number | null }[];
  if ([...rb].some((x) => !ra.has(x)) || between.length) {
    observed.push({ kind: "policy", title: "Policy revision in force differs", working: [...ra].sort().join(", ") || "none recorded", failing: [...rb].sort().join(", ") || "none recorded" });
    const last = Math.max(...ra, 0);
    if (last > 0)
      candidates.push({ kind: "policy", title: `A policy change after revision ${last}`, why: `Revisions published in the window: ${between.map((b) => b.revision).join(", ") || "none"}. Timing alone does not show the change caused the failure.`, test: { label: `Preview a rollback to revision ${last} (simulation first; publishing it needs your approval)`, action: `rollback_preview:${last}`, reversible: true } });
  }
  // 3. Destinations and verdicts.
  const dests = (rows: FlowRow[]) => {
    const m = new Map<string, Set<string>>();
    for (const r of rows.filter((x) => x.kind === "flow")) {
      const k = `${r.destination ?? "unknown"}${r.port ? `:${r.port}` : ""}`;
      (m.get(k) ?? m.set(k, new Set()).get(k)!).add(verdictOf(r));
    }
    return m;
  };
  const da = dests(A), db = dests(B);
  for (const [k, vs] of db) {
    const before = da.get(k);
    if (vs.has("deny") && !before?.has("deny")) {
      observed.push({ kind: "destination", title: `Now blocked: ${k}`, working: before ? [...before].join("/") : "not contacted", failing: [...vs].join("/") });
      candidates.push({ kind: "destination", title: `${k} is blocked while failing`, why: before ? "It was allowed or observed in the working interval." : "It was not contacted while working: the app may have started using a new destination.", test: { label: `Plan a 15-minute allow for ${k} scoped to this app and device (you review the exact plan)`, action: `plan_grant:${k}`, reversible: true } });
    } else if (!before) observed.push({ kind: "destination", title: `New destination: ${k}`, working: "not contacted", failing: [...vs].join("/") });
  }
  // 4. Endpoint health / coverage evidence and gaps.
  const cov = (rows: FlowRow[]) => [...new Set(rows.filter((r) => r.kind === "coverage" || r.kind === "activation_recovery" || r.kind === "session_not_adopted" || r.kind === "proxy_limit").map((r) => (r.kind === "coverage" ? r.detail ?? r.kind : `${r.kind}${r.detail ? ` (${r.detail})` : ""}`)))];
  const ca = cov(A), cb = cov(B);
  if (cb.join() !== ca.join()) {
    observed.push({ kind: "health", title: "Coverage or recovery state reported", working: ca.join(", ") || "no change reported", failing: cb.join(", ") || "no change reported" });
    if (cb.some((x) => x !== "enforced" && x !== "protected-session")) candidates.push({ kind: "health", title: "Enforcement health changed", why: `The endpoint reported: ${cb.join(", ")}.`, test: { label: "Open Diagnostics for this device", action: "open_diagnostics", reversible: true } });
  }
  const devices = dev ? [dev] : (c.devices() as { id: string }[]).map((d) => d.id);
  const gapsIn = (iv: Interval) => {
    const out: string[] = [];
    for (const d of devices) {
      const rows = c.flows.db.prepare("SELECT seq FROM flows WHERE device_id = ? AND at >= ? AND at < ? ORDER BY seq").all(d, iv.from, iv.to) as { seq: number }[];
      // The sequence span that could belong to this interval: after the last event before it, before the first after it.
      const before = c.flows.db.prepare("SELECT MAX(seq) AS s FROM flows WHERE device_id = ? AND at < ?").get(d, iv.from) as { s: number | null };
      const after = c.flows.db.prepare("SELECT MIN(seq) AS s FROM flows WHERE device_id = ? AND at >= ?").get(d, iv.to) as { s: number | null };
      const lo = (before.s ?? 0) + 1, hi = after.s === null ? Number.MAX_SAFE_INTEGER : after.s - 1;
      for (const [g0, g1] of c.flows.gaps(d)) if (g0 <= hi && g1 >= lo) out.push(`${d}: events ${g0}–${g1} missing`);
      if (rows.length === 0) out.push(`${d}: no events recorded in this interval`);
    }
    return out;
  };
  const ga = gapsIn(working), gb = gapsIn(failing);
  if (ga.length || gb.length) observed.push({ kind: "telemetry", title: "Telemetry gaps (comparison is incomplete here)", working: ga.join("; ") || "none", failing: gb.join("; ") || "none" });
  return {
    working,
    failing,
    device: dev,
    app: q.app ?? null,
    counts: { working: A.length, failing: B.length },
    observed,
    candidates,
    not_compared: ["Resolver and route changes (no resolver/route evidence is recorded by these endpoints)", "Capability history (only the current capability report is kept)"],
    disclaimer: "Observed changes are differences in recorded evidence. Candidates are possible explanations; none is claimed as the cause from timing alone. Every suggested test is reviewed by you and can be undone.",
  };
}

// ------------------------------------------------------------------------------------------------ Diagnostics

export function diagnostics(c: Controller, version: string) {
  const now = c.now();
  const devices = (c.devices() as unknown as { id: string; name: string; platform: string; last_seen_at: string | null; last_revision: number | null; coverage: string | null; stale: boolean; effective_coverage: string; coverage_note: string | null; capabilities: { capabilities?: Record<string, { support?: string; note?: string }> } | null; status: Record<string, unknown> | null; revision_states: { revision: number; state: string; at: string; detail: string | null }[]; telemetry_gaps: [number, number][] }[]).map((d) => {
    const seq = c.flows.db.prepare("SELECT max_seq FROM device_seq WHERE device_id = ?").get(d.id) as { max_seq: number } | undefined;
    const trial = d.revision_states.find((s) => s.state === "trial");
    const caps = Object.entries(d.capabilities?.capabilities ?? {});
    return {
      id: d.id,
      name: d.name,
      platform: d.platform,
      versions: { os: d.status?.os ?? null, endpoint: d.status?.version ?? null },
      policy: { applied: d.last_revision, latest_state: d.revision_states[0] ?? null, trial: trial && !d.revision_states.some((s) => s.revision === trial.revision && (s.state === "confirmed" || s.state === "rolled_back")) ? trial : null },
      health: { reported_coverage: d.coverage, effective_coverage: d.effective_coverage, stale: d.stale, note: d.coverage_note, evidence_age_s: d.last_seen_at ? Math.round((now.getTime() - Date.parse(d.last_seen_at)) / 1000) : null },
      capabilities: { supported: caps.filter(([, v]) => v.support === "supported").map(([k]) => k), downgraded: caps.filter(([, v]) => v.support !== "supported").map(([k, v]) => ({ key: k, support: v.support ?? "untested", note: v.note ?? null })) },
      spool: { acknowledged_seq: seq?.max_seq ?? 0, gaps: d.telemetry_gaps },
    };
  });
  const pubs = c.db.prepare("SELECT status, COUNT(*) AS n FROM publications GROUP BY status").all() as { status: string; n: number }[];
  const schema = c.db.prepare("SELECT v FROM schema_version").get() as { v: number };
  const flowSchema = c.flows.db.prepare("SELECT v FROM schema_version").get() as { v: number };
  return {
    generated_at: now.toISOString(),
    controller: { version, control_schema: schema.v, flow_schema: flowSchema.v, policy_revision: c.currentRevision()?.revision ?? null, publications: Object.fromEntries(pubs.map((p) => [p.status, p.n])) },
    devices,
    storage: { flow_db_bytes: c.flows.sizeBytes(), retention: c.flows.retention() },
    notifications: c.notifier.status(),
    compatibility_tests: { run: [], note: "No compatibility test has been explicitly selected and run from this controller." },
    limits: ["Routing and DNS context are not collected by these endpoints.", "The signer is a separate process; its health is shown by the last publication result, not probed here."],
  };
}
