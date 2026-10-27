/**
 * W14 quiet learning with poisoning resistance (MASTER_ROADMAP §9.4). Learning produces a proposal, never trust.
 *
 *   Capture  → bounded to one device, one executable identity, one named workflow and network context, a time window
 *              and a record budget. Existing rules stay enforced; capture only reads the flow store.
 *   Candidate→ exact destinations seen in the window, each `proposed`. Occurrence counts are shown, never used to
 *              accept anything. Completeness is "complete" only without gaps, pending holes or unknown identity.
 *   Review   → the owner selects entries one by one; an approved baseline is immutable (DB triggers).
 *   Enforce  → a baseline becomes a normal policy proposal (exact app + exact hosts), approved through the usual
 *              owner-authorized path; denies keep precedence.
 *   Drift    → new activity for the identity creates a new candidate; identity changes in the same family are listed;
 *              unused baseline entries are proposed for removal with a seasonal-use caveat. The baseline never mutates.
 *
 * Notification acknowledgement and mute live elsewhere and never allow anything.
 */
import { audit, HttpError, tx } from "./db.ts";
import { id, sha256hex } from "./crypto.ts";
import type { Controller, Principal } from "./controller.ts";

export const LEARNING_MIGRATIONS = `
CREATE TABLE IF NOT EXISTS captures (id TEXT PRIMARY KEY, device_id TEXT NOT NULL, exe TEXT NOT NULL, signer TEXT, workflow TEXT NOT NULL, network_context TEXT NOT NULL, started_at TEXT NOT NULL, ends_at TEXT NOT NULL, max_records INTEGER NOT NULL, status TEXT NOT NULL CHECK (status IN ('capturing','closed')), created_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS candidates (id TEXT PRIMARY KEY, capture_id TEXT, baseline_id TEXT, kind TEXT NOT NULL CHECK (kind IN ('capture','drift','import')), device_id TEXT NOT NULL, exe TEXT NOT NULL, signer TEXT, entries TEXT NOT NULL, completeness TEXT NOT NULL, incomplete_reasons TEXT NOT NULL, identity_changes TEXT NOT NULL, removal_proposals TEXT NOT NULL DEFAULT '[]', source TEXT, assumptions TEXT, created_at TEXT NOT NULL, status TEXT NOT NULL CHECK (status IN ('open','reviewed','discarded')));
CREATE TABLE IF NOT EXISTS baselines (id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, device_id TEXT NOT NULL, exe TEXT NOT NULL, signer TEXT, workflow TEXT, network_context TEXT, entries TEXT NOT NULL, digest TEXT NOT NULL, completeness TEXT NOT NULL, source TEXT, assumptions TEXT, approved_by TEXT NOT NULL, approved_at TEXT NOT NULL, supersedes TEXT);
CREATE TRIGGER IF NOT EXISTS baselines_immutable_u BEFORE UPDATE ON baselines BEGIN SELECT RAISE(ABORT, 'a reviewed baseline is immutable; new activity creates a new candidate'); END;
CREATE TRIGGER IF NOT EXISTS baselines_immutable_d BEFORE DELETE ON baselines BEGIN SELECT RAISE(ABORT, 'a reviewed baseline is immutable; retire it instead'); END;
CREATE TABLE IF NOT EXISTS baseline_retirements (baseline_id TEXT PRIMARY KEY, retired_by TEXT NOT NULL, retired_at TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incident_mutes (subject TEXT PRIMARY KEY, until TEXT NOT NULL, muted_by TEXT NOT NULL, created_at TEXT NOT NULL);
`;

export const MAX_CAPTURE_HOURS = 8;
export const MAX_CAPTURE_RECORDS = 20_000;
export const UNUSED_REMOVAL_DAYS = 30;

export interface Entry { destination: string; port: number | null; transport: string | null; occurrences: number; first_at: string; last_at: string; verdicts: string[]; status: "proposed" }

export function ensureLearning(c: Controller) {
  c.db.exec(LEARNING_MIGRATIONS);
}

function principalOwner(c: Controller, p: Principal) {
  return c.require(p, "owner");
}

export function startCapture(c: Controller, actor: Principal, b: { device_id?: unknown; exe?: unknown; signer?: unknown; workflow?: unknown; network_context?: unknown; hours?: unknown; max_records?: unknown }) {
  principalOwner(c, actor);
  ensureLearning(c);
  const device = String(b.device_id ?? "");
  const exe = String(b.exe ?? "");
  const workflow = String(b.workflow ?? "").trim();
  const ctx = String(b.network_context ?? "").trim();
  if (!c.db.prepare("SELECT 1 FROM devices WHERE id = ? AND revoked_at IS NULL").get(device)) throw new HttpError(404, "unknown device");
  if (!exe.startsWith("/")) throw new HttpError(400, "capture is bound to one exact executable path (a name is not identity)");
  if (!workflow || !ctx) throw new HttpError(400, "name the workflow (e.g. 'npm install') and network context (e.g. 'home LAN'); a normal session and a dependency install are different captures");
  const hours = Number(b.hours ?? 1);
  if (!(hours > 0 && hours <= MAX_CAPTURE_HOURS)) throw new HttpError(400, `capture lasts at most ${MAX_CAPTURE_HOURS} hours`);
  const max = Math.min(Number(b.max_records ?? 5000), MAX_CAPTURE_RECORDS);
  const now = c.now();
  const cid = id("cap");
  c.db.prepare("INSERT INTO captures (id, device_id, exe, signer, workflow, network_context, started_at, ends_at, max_records, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'capturing', ?)")
    .run(cid, device, exe, b.signer ? String(b.signer) : null, workflow.slice(0, 120), ctx.slice(0, 120), now.toISOString(), new Date(now.getTime() + hours * 3600_000).toISOString(), max, actor.id);
  audit(c.db, now, actor.id, "learning.capture.start", cid, { device, exe, workflow, ctx, hours });
  return { id: cid, note: "Existing rules stay enforced during capture. Nothing seen during capture is trusted until you review it." };
}

interface FlowRow { seq: number; at: string; destination: string | null; port: number | null; transport: string | null; verdict: string | null; observed: number; exe: string | null; signer: string | null; app: string | null }

function entriesFrom(rows: FlowRow[]): Entry[] {
  const m = new Map<string, Entry>();
  for (const r of rows) {
    const k = `${r.destination}|${r.port}|${r.transport}`;
    const v = r.verdict === "deny" ? "deny" : r.observed ? "observed" : "allow";
    const e = m.get(k);
    if (e) {
      e.occurrences++;
      if (r.at < e.first_at) e.first_at = r.at;
      if (r.at > e.last_at) e.last_at = r.at;
      if (!e.verdicts.includes(v)) e.verdicts.push(v);
    } else m.set(k, { destination: r.destination ?? "unknown", port: r.port, transport: r.transport, occurrences: 1, first_at: r.at, last_at: r.at, verdicts: [v], status: "proposed" });
  }
  return [...m.values()].sort((a, b) => a.destination.localeCompare(b.destination) || (a.port ?? 0) - (b.port ?? 0));
}

/** Why the evidence cannot support a "complete" claim for this window. */
function incompleteness(c: Controller, device: string, from: string, to: string, exe: string, family: string | null): string[] {
  const reasons: string[] = [];
  const seqs = c.flows.db.prepare("SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM flows WHERE device_id = ? AND at >= ? AND at < ?").get(device, from, to) as { lo: number | null; hi: number | null };
  for (const [a, b] of c.flows.gaps(device)) if (seqs.lo !== null && a <= seqs.hi! + 1 && b >= seqs.lo - 1) reasons.push(`events ${a}–${b} were lost on or before delivery`);
  const ack = c.flows.ackState(device);
  if (seqs.hi !== null && ack.acked < seqs.hi) reasons.push(`events after #${ack.acked} have not all arrived yet`);
  const unknown = c.flows.db.prepare("SELECT COUNT(*) AS n FROM flows WHERE device_id = ? AND kind = 'flow' AND at >= ? AND at < ? AND exe IS NULL").get(device, from, to) as { n: number };
  if (unknown.n) reasons.push(`${unknown.n} connection(s) in the window had no executable identity and cannot be attributed`);
  if (family) {
    const other = c.flows.db.prepare("SELECT DISTINCT exe, signer FROM flows WHERE device_id = ? AND kind = 'flow' AND at >= ? AND at < ? AND app = ? AND exe IS NOT NULL AND exe != ?").all(device, from, to, family, exe) as { exe: string; signer: string | null }[];
    if (other.length) reasons.push(`the same family ran from other identities in the window: ${other.map((o) => o.exe).join(", ")}`);
  }
  return reasons;
}

function identityChanges(c: Controller, device: string, exe: string, signer: string | null, since: string): { exe: string; signer: string | null; first_at: string }[] {
  const fam = c.flows.db.prepare("SELECT app FROM flows WHERE device_id = ? AND exe = ? AND app IS NOT NULL LIMIT 1").get(device, exe) as { app: string } | undefined;
  const rows = c.flows.db.prepare("SELECT exe, signer, MIN(at) AS first_at FROM flows WHERE device_id = ? AND kind = 'flow' AND at >= ? AND exe IS NOT NULL GROUP BY exe, signer").all(device, since) as { exe: string; signer: string | null; first_at: string }[];
  const base = exe.split("/").pop();
  return rows.filter((r) => (r.exe !== exe || (r.signer ?? null) !== (signer ?? null)) && (r.exe.split("/").pop() === base || (fam && (c.flows.db.prepare("SELECT 1 FROM flows WHERE exe = ? AND app = ? LIMIT 1").get(r.exe, fam.app) as unknown))));
}

/** Close a capture and produce its candidate. Callable early by the owner, or once the window ends. */
export function closeCapture(c: Controller, actor: Principal, captureId: string) {
  principalOwner(c, actor);
  ensureLearning(c);
  const cap = c.db.prepare("SELECT * FROM captures WHERE id = ?").get(captureId) as { id: string; device_id: string; exe: string; signer: string | null; started_at: string; ends_at: string; max_records: number; status: string } | undefined;
  if (!cap) throw new HttpError(404, "no such capture");
  if (cap.status !== "capturing") throw new HttpError(409, "capture already closed");
  const end = c.now().toISOString() < cap.ends_at ? c.now().toISOString() : cap.ends_at;
  const rows = c.flows.db.prepare(`SELECT seq, at, destination, port, transport, verdict, observed, exe, signer, app FROM flows WHERE device_id = ? AND kind = 'flow' AND at >= ? AND at < ? AND exe = ? AND IFNULL(signer, '') = ? ORDER BY seq LIMIT ?`)
    .all(cap.device_id, cap.started_at, end, cap.exe, cap.signer ?? "", cap.max_records + 1) as unknown as FlowRow[];
  const reasons = incompleteness(c, cap.device_id, cap.started_at, end, cap.exe, rows[0]?.app ?? null);
  if (rows.length > cap.max_records) reasons.push(`the record budget (${cap.max_records}) was reached; later activity was not considered`);
  const entries = entriesFrom(rows.slice(0, cap.max_records));
  const cid = id("cand");
  tx(c.db, () => {
    c.db.prepare("UPDATE captures SET status = 'closed' WHERE id = ?").run(cap.id);
    c.db.prepare("INSERT INTO candidates (id, capture_id, kind, device_id, exe, signer, entries, completeness, incomplete_reasons, identity_changes, created_at, status) VALUES (?, ?, 'capture', ?, ?, ?, ?, ?, ?, ?, ?, 'open')")
      .run(cid, cap.id, cap.device_id, cap.exe, cap.signer, JSON.stringify(entries), reasons.length ? "incomplete" : "complete", JSON.stringify(reasons), JSON.stringify(identityChanges(c, cap.device_id, cap.exe, cap.signer, cap.started_at)), c.now().toISOString());
  });
  return candidate(c, cid);
}

export interface CandidateView { id: string; capture_id: string | null; baseline_id: string | null; kind: "capture" | "drift" | "import"; device_id: string; exe: string; signer: string | null; entries: Entry[]; completeness: "complete" | "incomplete"; incomplete_reasons: string[]; identity_changes: { exe: string; signer: string | null; first_at: string }[]; removal_proposals: { destination: string; port: number | null; caveat: string }[]; source: string | null; assumptions: Record<string, unknown> | null; created_at: string; status: string; note: string }

export function candidate(c: Controller, cid: string): CandidateView {
  ensureLearning(c);
  const r = c.db.prepare("SELECT * FROM candidates WHERE id = ?").get(cid) as Record<string, string> | undefined;
  if (!r) throw new HttpError(404, "no such candidate");
  return { ...r, entries: JSON.parse(r.entries!) as Entry[], incomplete_reasons: JSON.parse(r.incomplete_reasons!), identity_changes: JSON.parse(r.identity_changes!), removal_proposals: JSON.parse(r.removal_proposals!), assumptions: r.assumptions ? JSON.parse(r.assumptions) : null, note: "Every entry is proposed. Occurring during capture, or occurring often, does not make it trusted." } as unknown as CandidateView;
}

/**
 * Owner review: accept exactly the listed entries (by index). Unlisted entries are excluded. The result is a new,
 * immutable baseline; an earlier baseline for the identity is superseded, never edited.
 */
export function approveCandidate(c: Controller, actor: Principal, cid: string, b: { accept?: unknown; acknowledge_incomplete?: unknown }) {
  principalOwner(c, actor);
  const cand = candidate(c, cid);
  if (cand.status !== "open") throw new HttpError(409, "candidate already reviewed");
  const accept = Array.isArray(b.accept) ? (b.accept as unknown[]).map(Number) : null;
  if (!accept || accept.some((i) => !Number.isInteger(i) || i < 0 || i >= cand.entries.length)) throw new HttpError(400, "accept must list the entry indexes you reviewed and want; nothing is accepted by default");
  if (cand.completeness === "incomplete" && b.acknowledge_incomplete !== true) throw new HttpError(409, `the evidence is incomplete (${cand.incomplete_reasons.join("; ")}); acknowledge that explicitly to approve a partial baseline`);
  const deny = accept.filter((i) => cand.entries[i]!.verdicts.includes("deny") && cand.entries[i]!.verdicts.length === 1);
  const cap = cand.capture_id ? (c.db.prepare("SELECT workflow, network_context FROM captures WHERE id = ?").get(cand.capture_id) as { workflow: string; network_context: string } | undefined) : undefined;
  const prev = c.db.prepare("SELECT b.id FROM baselines b WHERE b.device_id = ? AND b.exe = ? AND IFNULL(b.signer,'') = ? AND NOT EXISTS (SELECT 1 FROM baseline_retirements r WHERE r.baseline_id = b.id) ORDER BY b.approved_at DESC LIMIT 1").get(cand.device_id, cand.exe, cand.signer ?? "") as { id: string } | undefined;
  // a drift candidate adds to the previous baseline's entries; a capture candidate stands alone
  const prevEntries = cand.kind === "drift" && prev ? (JSON.parse((c.db.prepare("SELECT entries FROM baselines WHERE id = ?").get(prev.id) as { entries: string }).entries) as Entry[]) : [];
  const entries = [...prevEntries, ...accept.map((i) => cand.entries[i]!)];
  const bid = id("base");
  const digest = "sha256:" + sha256hex(JSON.stringify({ exe: cand.exe, signer: cand.signer, entries: entries.map((e) => [e.destination, e.port, e.transport]) }));
  tx(c.db, () => {
    c.db.prepare("INSERT INTO baselines (id, candidate_id, device_id, exe, signer, workflow, network_context, entries, digest, completeness, source, assumptions, approved_by, approved_at, supersedes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(bid, cid, cand.device_id, cand.exe, cand.signer ?? null, cap?.workflow ?? null, cap?.network_context ?? null, JSON.stringify(entries), digest, cand.completeness, cand.source ?? null, cand.assumptions ? JSON.stringify(cand.assumptions) : null, actor.id, c.now().toISOString(), prev?.id ?? null);
    c.db.prepare("UPDATE candidates SET status = 'reviewed' WHERE id = ?").run(cid);
    audit(c.db, c.now(), actor.id, "learning.baseline.approve", bid, { candidate: cid, accepted: accept.length, of: cand.entries.length, denied_only_entries: deny.length });
  });
  return baseline(c, bid);
}

export interface BaselineView { id: string; candidate_id: string; device_id: string; exe: string; signer: string | null; workflow: string | null; network_context: string | null; entries: Entry[]; digest: string; completeness: string; source: string | null; assumptions: Record<string, unknown> | null; approved_by: string; approved_at: string; supersedes: string | null; retired: unknown }

export function baseline(c: Controller, bid: string): BaselineView {
  ensureLearning(c);
  const r = c.db.prepare("SELECT * FROM baselines WHERE id = ?").get(bid) as Record<string, string> | undefined;
  if (!r) throw new HttpError(404, "no such baseline");
  const retired = c.db.prepare("SELECT * FROM baseline_retirements WHERE baseline_id = ?").get(bid) ?? null;
  return { ...r, entries: JSON.parse(r.entries!) as Entry[], assumptions: r.assumptions ? JSON.parse(r.assumptions) : null, retired } as unknown as BaselineView;
}

/** Drift review: activity since approval that the baseline does not cover becomes a NEW candidate. */
export function driftReview(c: Controller, actor: Principal, bid: string) {
  principalOwner(c, actor);
  const b = baseline(c, bid);
  if (b.retired) throw new HttpError(409, "baseline is retired");
  const rows = c.flows.db.prepare("SELECT seq, at, destination, port, transport, verdict, observed, exe, signer, app FROM flows WHERE device_id = ? AND kind = 'flow' AND at >= ? AND exe = ? AND IFNULL(signer, '') = ? ORDER BY seq LIMIT ?")
    .all(b.device_id, b.approved_at, b.exe, b.signer ?? "", MAX_CAPTURE_RECORDS) as unknown as FlowRow[];
  const covered = new Set(b.entries.map((e) => `${e.destination}|${e.port}|${e.transport}`));
  // exact destinations only: a covering service group never hides a new host
  const fresh = entriesFrom(rows.filter((r) => !covered.has(`${r.destination}|${r.port}|${r.transport}`)));
  const used = new Set(rows.map((r) => `${r.destination}|${r.port}|${r.transport}`));
  const unusedSince = new Date(c.now().getTime() - UNUSED_REMOVAL_DAYS * 86400_000).toISOString();
  const removals = b.approved_at < unusedSince ? b.entries.filter((e) => !used.has(`${e.destination}|${e.port}|${e.transport}`)).map((e) => ({ destination: e.destination, port: e.port, caveat: `unused for ${UNUSED_REMOVAL_DAYS}+ days; seasonal or rare workflows (yearly tax software, travel) may still need it` })) : [];
  const changes = identityChanges(c, b.device_id, b.exe, b.signer ?? null, b.approved_at);
  const reasons = incompleteness(c, b.device_id, b.approved_at, c.now().toISOString(), b.exe, rows[0]?.app ?? null);
  if (!fresh.length && !removals.length && !changes.length) return { baseline: bid, drift: false, note: "No new activity, identity change or unused entry since approval." };
  const cid = id("cand");
  c.db.prepare("INSERT INTO candidates (id, baseline_id, kind, device_id, exe, signer, entries, completeness, incomplete_reasons, identity_changes, removal_proposals, created_at, status) VALUES (?, ?, 'drift', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')")
    .run(cid, bid, b.device_id, b.exe, b.signer ?? null, JSON.stringify(fresh), reasons.length ? "incomplete" : "complete", JSON.stringify(reasons), JSON.stringify(changes), JSON.stringify(removals), c.now().toISOString());
  return { baseline: bid, drift: true, candidate: candidate(c, cid) };
}

/** Imported baselines keep where they came from and what they assume. */
export function importCandidate(c: Controller, actor: Principal, b: { device_id?: unknown; exe?: unknown; signer?: unknown; entries?: unknown; source?: unknown; assumptions?: unknown }) {
  principalOwner(c, actor);
  ensureLearning(c);
  const source = String(b.source ?? "").trim();
  const assumptions = b.assumptions as { app_version?: string; platform?: string; capabilities?: string[] } | undefined;
  if (!source) throw new HttpError(400, "an imported baseline must name its source");
  if (!assumptions || !assumptions.app_version || !assumptions.platform) throw new HttpError(400, "an imported baseline must state its compatibility assumptions (app_version, platform)");
  const exe = String(b.exe ?? "");
  if (!exe.startsWith("/")) throw new HttpError(400, "an imported baseline is bound to one exact executable");
  const list = (Array.isArray(b.entries) ? b.entries : []) as { destination?: string; port?: number; transport?: string }[];
  if (!list.length || list.some((e) => !e.destination || e.destination.includes("*"))) throw new HttpError(400, "entries must be exact destinations (no wildcards)");
  const entries: Entry[] = list.map((e) => ({ destination: e.destination!, port: e.port ?? null, transport: e.transport ?? null, occurrences: 0, first_at: "", last_at: "", verdicts: [], status: "proposed" }));
  const cid = id("cand");
  c.db.prepare("INSERT INTO candidates (id, kind, device_id, exe, signer, entries, completeness, incomplete_reasons, identity_changes, source, assumptions, created_at, status) VALUES (?, 'import', ?, ?, ?, ?, 'incomplete', ?, '[]', ?, ?, ?, 'open')")
    .run(cid, String(b.device_id ?? ""), exe, b.signer ? String(b.signer) : null, JSON.stringify(entries), JSON.stringify(["imported: not observed on this device"]), source, JSON.stringify(assumptions), c.now().toISOString());
  return candidate(c, cid);
}

export function retireBaseline(c: Controller, actor: Principal, bid: string, reason: unknown) {
  principalOwner(c, actor);
  baseline(c, bid);
  c.db.prepare("INSERT INTO baseline_retirements (baseline_id, retired_by, retired_at, reason) VALUES (?, ?, ?, ?)").run(bid, actor.id, c.now().toISOString(), String(reason ?? "retired by owner").slice(0, 200));
  return baseline(c, bid);
}

/** The policy text a baseline would add: exact app selector + exact hosts/addresses. Proposed through the normal
 * owner-authorized path (it is broadening, so it needs the owner key); denies keep precedence. */
export function baselineRules(b: { id: string; exe: string; signer: string | null; entries: Entry[] }): string {
  const sel = b.signer ? `{ executable = "${b.exe}", team_id = "${b.signer.split("/")[0]}" }` : `{ executable = "${b.exe}" }`;
  return b.entries
    .filter((e) => e.destination !== "unknown")
    .map((e, i) => {
      const isIp = /^[0-9.:a-f]+$/i.test(e.destination) && /[.:]/.test(e.destination);
      const dest = isIp ? `cidrs = ["${e.destination}${e.destination.includes(":") ? "/128" : "/32"}"]` : `hosts = ["${e.destination}"]`;
      return `\n[[rules]]\nid = "baseline-${b.id.slice(-8)}-${i}"\ndescription = "From reviewed baseline ${b.id}"\naction = "allow"\non_unsupported = "skip_with_report"\nselector = { apps = [${sel}] }\ndestinations = { ${dest} }\n${e.transport && e.transport !== "any" ? `transport = "${e.transport}"\n` : ""}${e.port ? `ports = [${e.port}]\n` : ""}provenance = { kind = "owner_action", reference = "reviewed baseline ${b.id}" }\n`;
    })
    .join("");
}

export async function proposeBaseline(c: Controller, actor: Principal, bid: string) {
  principalOwner(c, actor);
  const b = baseline(c, bid);
  if (b.retired) throw new HttpError(409, "baseline is retired");
  const cur = c.currentRevision();
  if (!cur) throw new HttpError(409, "no policy to extend yet");
  return c.propose(actor, cur.source + baselineRules({ id: b.id, exe: b.exe, signer: b.signer ?? null, entries: b.entries }), `Enforce reviewed baseline ${b.id}`);
}

// ------------------------------------------------------------------------------------------------ notification mutes

/** Mute = suppress notifications for one stable subject. It changes no policy, no verdict and no incident state. */
export function muteIncident(c: Controller, actor: Principal, iid: string, minutes: unknown) {
  principalOwner(c, actor);
  ensureLearning(c);
  const inc = c.db.prepare("SELECT dedup_key FROM incidents WHERE id = ?").get(iid) as { dedup_key: string } | undefined;
  if (!inc) throw new HttpError(404, "no such incident");
  const m = Number(minutes ?? 60);
  if (!(m > 0 && m <= 7 * 24 * 60)) throw new HttpError(400, "mute for 1 minute to 7 days");
  const until = new Date(c.now().getTime() + m * 60_000).toISOString();
  c.db.prepare("INSERT INTO incident_mutes (subject, until, muted_by, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (subject) DO UPDATE SET until = excluded.until").run(inc.dedup_key, until, actor.id, c.now().toISOString());
  audit(c.db, c.now(), actor.id, "incident.mute", iid, { until });
  return { incident: iid, muted_until: until, note: "Muted means no notifications for this subject. It does not allow anything." };
}

export function isMuted(c: Controller, dedupKey: string): boolean {
  ensureLearning(c);
  const subject = dedupKey.split("#")[0]!;
  const r = c.db.prepare("SELECT until FROM incident_mutes WHERE subject = ?").get(subject) as { until: string } | undefined;
  return !!r && r.until > c.now().toISOString();
}

// ------------------------------------------------------------------------------------------------ review surfaces

export type CaptureState = "capturing" | "window_ended" | "closed";
export interface CaptureView { id: string; device_id: string; exe: string; signer: string | null; workflow: string; network_context: string; started_at: string; ends_at: string; max_records: number; status: string; state: CaptureState; created_by: string; candidate_id: string | null }

/**
 * The permission diff a reviewer sees for a candidate: which entries would broaden the identity's current reviewed
 * baseline, which it already covers, and which were only ever refused. Exact destinations; never collapsed to a group.
 */
export function permissionDiff(c: Controller, cand: CandidateView) {
  const prev = c.db.prepare("SELECT b.id, b.entries FROM baselines b WHERE b.device_id = ? AND b.exe = ? AND IFNULL(b.signer,'') = ? AND NOT EXISTS (SELECT 1 FROM baseline_retirements r WHERE r.baseline_id = b.id) ORDER BY b.approved_at DESC LIMIT 1")
    .get(cand.device_id, cand.exe, cand.signer ?? "") as { id: string; entries: string } | undefined;
  const covered = new Set((prev ? (JSON.parse(prev.entries) as Entry[]) : []).map((e) => `${e.destination}|${e.port}|${e.transport}`));
  const rows = cand.entries.map((e, index) => ({
    index,
    destination: e.destination,
    port: e.port,
    transport: e.transport,
    occurrences: e.occurrences,
    change: covered.has(`${e.destination}|${e.port}|${e.transport}`) ? ("in_baseline" as const) : ("adds" as const),
    unknown_destination: e.destination === "unknown",
    denied_only: e.verdicts.length === 1 && e.verdicts[0] === "deny",
  }));
  return {
    baseline_id: prev?.id ?? null,
    adds: rows.filter((r) => r.change === "adds").length,
    rows,
    removals: cand.removal_proposals,
    note: "Accepting an entry adds an exact allow for this identity once you enforce the baseline with your owner key. Denies keep precedence.",
  };
}

/** Everything the learning screens list: captures, the review queue, the drift queue and baselines. */
export function learningOverview(c: Controller) {
  ensureLearning(c);
  const now = c.now().toISOString();
  const caps = (c.db.prepare("SELECT * FROM captures ORDER BY started_at DESC LIMIT 50").all() as unknown as Omit<CaptureView, "state" | "candidate_id">[]).map((x) => ({
    ...x,
    state: (x.status === "closed" ? "closed" : x.ends_at <= now ? "window_ended" : "capturing") as CaptureState,
    candidate_id: (c.db.prepare("SELECT id FROM candidates WHERE capture_id = ?").get(x.id) as { id: string } | undefined)?.id ?? null,
  }));
  const cands = (c.db.prepare("SELECT id FROM candidates ORDER BY created_at DESC LIMIT 100").all() as { id: string }[]).map((r) => {
    const v = candidate(c, r.id);
    return { ...v, permission_diff: permissionDiff(c, v) };
  });
  const bases = (c.db.prepare("SELECT id FROM baselines ORDER BY approved_at DESC LIMIT 100").all() as { id: string }[]).map((r) => baseline(c, r.id));
  return {
    captures: caps,
    review_queue: cands.filter((x) => x.status === "open" && x.kind !== "drift"),
    drift_queue: cands.filter((x) => x.status === "open" && x.kind === "drift"),
    reviewed: cands.filter((x) => x.status !== "open").slice(0, 20),
    baselines: bases,
    limits: { max_capture_hours: MAX_CAPTURE_HOURS, max_capture_records: MAX_CAPTURE_RECORDS, unused_removal_days: UNUSED_REMOVAL_DAYS },
  };
}

/** Owner discards a candidate ("more evidence needed"): nothing is accepted, the baseline is untouched. */
export function discardCandidate(c: Controller, actor: Principal, cid: string) {
  principalOwner(c, actor);
  const cand = candidate(c, cid);
  if (cand.status !== "open") throw new HttpError(409, "candidate already reviewed");
  c.db.prepare("UPDATE candidates SET status = 'discarded' WHERE id = ?").run(cid);
  audit(c.db, c.now(), actor.id, "learning.candidate.discard", cid, {});
  return candidate(c, cid);
}
