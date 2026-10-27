/**
 * The policy signer: a separate identity from the controller.
 *
 * It holds the snapshot signing key and its own list of owner public keys (a file the controller cannot write in a
 * real deployment: run it as the `moat-signer` user with `moat-signer serve`). It never signs bytes the controller
 * hands it. It receives the base policy *source* plus the temporary grants as `moat.grant.v1` objects, compiles them
 * itself with `moatctl compile --grants` (the Rust core turns each grant into its exact device/app/task rule and binds
 * every overlay into `report.effective_digest`), and decides from structured evidence only:
 *
 *   - the base policy is compared with the last base it signed using `moatctl diff`; the decision reads
 *     `diff.changes[].direction` (W02), never the human `broadening` text. Any `broadening` change needs a valid
 *     owner-key signature over the exact source.
 *   - grants are compared by id and authority digest with the last grant set it signed. Removing one only removes
 *     authority. A new grant must be an exact `moat.grant.v1` (one device, one app or task, one destination, one
 *     port, at most 24 h, bound to the digest of this base) and be authorized by
 *       * a delegated issuer (a phone) whose owner-signed delegation covers the grant's kind, device and lifetime and
 *         who signed this exact grant's digest ............................................ ("delegated_issuer")
 *       * or, only when this signer was started with MOAT_SIGNER_CONTROLLER_GRANTS=1 (off by default), the
 *         controller's attestation that an authenticated owner session asked ............ ("temporary_grant_overlay")
 *   - a grant id cannot be reused with different content, and a removed (revoked) grant cannot be re-added.
 *   - process-scoped grants are refused: no endpoint enforces a process-generation selector yet.
 *
 * Every signature is journaled by publication id before it is returned, so a controller that lost the reply can
 * recover the same revision instead of minting a conflicting one.
 */
import { existsSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { canonicalJson, delegationString, grantApprovalString, keyPairFromSeed, ownerAuthorizationString, publicFromHex, keyIdOf, sha256hex, signSnapshotBytes, verifyB64, type KeyPair, type SignedSnapshot } from "./crypto.ts";
import type { Moatctl } from "./moatctl.ts";

export const MAX_GRANT_SECONDS = 24 * 3600;
const JOURNAL_KEEP = 64;
const CLOCK_SKEW_MS = 15 * 60_000;

export interface OwnerAuthorization { key_id: string; signature: string }

/** `moat.grant.v1` (contracts/schemas/moat.grant.v1.schema.json). Optional fields are omitted, never null. */
export interface GrantV1 {
  schema: "moat.grant.v1";
  grant_id: string;
  idempotency_key: string;
  scope: {
    kind: "app_on_device" | "process_instance" | "task";
    device_id: string;
    boot_id?: string;
    task_id?: string;
    process?: { pid: number; start_generation: number };
    executable?: { path?: string; team_id?: string; signing_id?: string; bundle_id?: string; digest?: string };
  };
  destination: { kind: "address"; address: string } | { kind: "hostname"; hostname: string };
  transport: "tcp" | "udp";
  port: number;
  issued_at: string;
  not_before: string;
  admission_until: string;
  stream_policy: "admission_only" | "terminate_at_deadline";
  base_policy_digest: string;
  issuer: { principal: string; role: "owner" | "delegated"; key_id?: string };
  approval_digest: string;
  reason?: string;
}

/** What the person was shown and approved besides the grant itself. `grant.approval_digest` = digest of this. */
export interface ApprovalContext {
  schema: "moat.grant_context.v1";
  kind: "allow_once" | "temporary";
  policy_revision: number;
  requested_by: string;
  incident?: { id: string; revision: number };
}

/** Owner-signed delegation of a bounded approval scope to another key (e.g. a phone's browser). */
export interface Delegation {
  schema: "moat.delegation.v1";
  issuer_key_id: string;
  issuer_public_hex: string;
  label: string;
  scope: { kinds: string[]; devices: string[]; max_ttl_seconds: number };
  not_after: string;
  owner_key_id: string;
  signature: string;
}

/** A delegated issuer's signature over one exact grant (`moat-grant-approval-v1\n<grantDigest>\n`). */
export interface GrantApproval { grant_id: string; context: ApprovalContext; delegation: Delegation; issuer_signature: string }

export interface SignRequest {
  /** Journal key: the same publication id always yields the same signed revision. */
  publicationId?: string;
  /** Proposal or grant id the owner authorized (bound into the authorization). */
  subject: string;
  /** The reviewed base policy (TOML or JSON). Grants are never rendered into it. */
  source: string;
  /** Every live temporary grant (W03 overlay), as `moat.grant.v1` objects. */
  grants?: GrantV1[];
  revision: number;
  rollbackOf?: number | null;
  platforms: ("linux" | "macos" | "dns")[];
  /**
   * Per-platform device lists (issue #26). A platform with enrolled devices is compiled for exactly those devices, so
   * an app-scoped or hostname rule scoped to a Mac does not refuse the Linux snapshot in a mixed fleet; the device
   * list is inside the signed payload. A platform with no list (or an empty one) is compiled fleet-wide.
   */
  targets?: Partial<Record<"linux" | "macos" | "dns", string[]>>;
  ownerAuthorization?: OwnerAuthorization | null;
  /** Controller attestation that an authenticated owner session requested the new owner-issued grants (only honored when enabled). */
  ownerSessionAttested?: boolean;
  /** Delegated-issuer approvals, one per new delegated grant. */
  grantApprovals?: GrantApproval[];
  issuedAt: Date;
}
export type AuthorizedBy = "narrowing" | "temporary_grant_overlay" | "delegated_issuer" | "owner_key";
export interface SignResult {
  revision: number;
  publication_id: string | null;
  snapshots: { platform: string; signed: SignedSnapshot; report: unknown }[];
  /** Human summary of what needed authority (display only; the decision used structured fields). */
  broadening: string[];
  authorizedBy: AuthorizedBy;
  issuers?: string[];
  /** Grant ids carried by this revision, and the core's effective-policy digest (base + overlays + compiler). */
  grants?: string[];
  effective_digest?: string | null;
}

export interface SemanticChange { item: string; kind: string; direction: "broadening" | "narrowing" | "neutral"; fields?: string[]; detail: string }

interface JournalEntry { id: string; revision: number; digest: string; result: SignResult }
interface SignerState {
  last_revision: number;
  last_source: string | null;
  /** grant id → authority digest of every grant in the last signed revision */
  last_grants?: Record<string, string>;
  /** grant id → original deadline, for grants removed before their deadline (never re-added) */
  retired?: Record<string, string>;
  journal?: JournalEntry[];
}

export class SignerError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Canonical digest of a contract object (contracts/README.md rule 9): what a delegated issuer signs. */
export function grantDigest(g: GrantV1): string {
  return `sha256:${sha256hex(canonicalJson(g))}`;
}
/** Authority digest: the grant without its display-only `reason` (Grant::authority_digest). */
export function authorityDigest(g: GrantV1): string {
  const { reason: _r, ...rest } = g;
  return `sha256:${sha256hex(canonicalJson(rest))}`;
}
export function contextDigest(c: ApprovalContext): string {
  return `sha256:${sha256hex(canonicalJson(c))}`;
}
/** sha256 policy digest of a normalized policy (`moatctl normalize` output, canonical JSON). */
export function policyDigest(normalized: unknown): string {
  return `sha256:${sha256hex(canonicalJson(normalized))}`;
}
/** Canonical contract timestamp: UTC, whole seconds. */
export const contractTime = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

/** Structural problems with a grant this signer refuses regardless of who approved it, or null. */
export function grantProblem(g: GrantV1, baseDigest: string): string | null {
  if (g?.schema !== "moat.grant.v1") return "not a moat.grant.v1 object";
  if (g.scope?.kind === "process_instance") return "process-scoped grants are unavailable: no endpoint enforces a process-generation selector yet";
  if (g.scope?.kind !== "app_on_device" && g.scope?.kind !== "task") return "unsupported grant scope";
  if (!g.scope.device_id) return "a grant must name exactly one device";
  if (g.scope.kind === "app_on_device" && !g.scope.executable) return "an app grant must name its executable";
  if (g.scope.kind === "task" && (!g.scope.task_id || !g.scope.boot_id)) return "a task grant must name its task and boot";
  if (g.base_policy_digest !== baseDigest) return `approved against ${g.base_policy_digest}, not the current base policy ${baseDigest}`;
  const nb = Date.parse(g.not_before);
  const until = Date.parse(g.admission_until);
  if (!(until > nb) || (until - nb) / 1000 > MAX_GRANT_SECONDS) return `admission window must be positive and at most ${MAX_GRANT_SECONDS / 3600}h`;
  return null;
}

export class Signer {
  private kp: KeyPair;
  private ownerKeys: Map<string, string>;
  private state: SignerState;
  private statePath: string | null;
  private moatctl: Moatctl;
  readonly controllerAttestedGrants: boolean;
  constructor(opts: { seedHex: string; ownerPublicKeysHex: string[]; moatctl: Moatctl; statePath?: string | null; controllerAttestedGrants?: boolean }) {
    this.kp = keyPairFromSeed(opts.seedHex);
    this.ownerKeys = new Map(opts.ownerPublicKeysHex.map((h) => [keyIdOf(h.trim()), h.trim()]));
    this.moatctl = opts.moatctl;
    this.statePath = opts.statePath ?? null;
    this.controllerAttestedGrants = opts.controllerAttestedGrants ?? false;
    this.state = this.statePath && existsSync(this.statePath) ? (JSON.parse(readFileSync(this.statePath, "utf8")) as SignerState) : { last_revision: 0, last_source: null };
    this.state.journal ??= [];
    this.state.last_grants ??= {};
    this.state.retired ??= {};
  }

  get keyId() {
    return this.kp.keyId;
  }
  get publicHex() {
    return this.kp.publicHex;
  }
  get lastRevision() {
    return this.state.last_revision;
  }

  /** The signed result for a publication id, if this signer signed it (lost-reply recovery). */
  async publication(id: string): Promise<SignResult | null> {
    return this.state.journal?.find((j) => j.id === id)?.result ?? null;
  }

  private save() {
    if (!this.statePath) return;
    writeFileSync(`${this.statePath}.tmp`, JSON.stringify(this.state));
    renameSync(`${this.statePath}.tmp`, this.statePath);
  }

  private async normalize(source: string): Promise<unknown> {
    const r = await this.moatctl.run(["normalize", "@p.toml"], { "p.toml": source });
    if (r.code !== 0) throw new SignerError(422, `policy invalid: ${(r.stderr || r.stdout).trim()}`);
    return JSON.parse(r.stdout) as unknown;
  }

  /** Does a delegated-issuer approval authorize exactly this grant? Returns a reason or null. */
  private checkApproval(g: GrantV1, a: GrantApproval, issuedAt: Date): string | null {
    const del = a.delegation;
    if (a.grant_id !== g.grant_id) return "approval names a different grant";
    if (g.issuer.role !== "delegated" || g.issuer.key_id !== del.issuer_key_id) return "the grant does not name this delegated issuer";
    if (a.context?.schema !== "moat.grant_context.v1" || contextDigest(a.context) !== g.approval_digest) return "approval context does not match the grant's approval digest";
    const ownerHex = this.ownerKeys.get(del.owner_key_id);
    if (!ownerHex) return "delegation is not signed by a trusted owner key";
    const { signature, ...body } = del;
    if (!verifyB64(publicFromHex(ownerHex), delegationString(body), signature)) return "delegation signature invalid";
    if (keyIdOf(del.issuer_public_hex) !== del.issuer_key_id) return "delegation issuer key id mismatch";
    if (!(Date.parse(del.not_after) > issuedAt.getTime())) return "delegation expired";
    if (!del.scope.kinds.includes(a.context.kind)) return `delegation does not cover ${a.context.kind}`;
    if (!del.scope.devices.includes(g.scope.device_id)) return `delegation does not cover device ${g.scope.device_id}`;
    const ttl = (Date.parse(g.admission_until) - Date.parse(g.issued_at)) / 1000;
    if (!(ttl > 0 && ttl <= Math.min(del.scope.max_ttl_seconds, MAX_GRANT_SECONDS))) return `lifetime exceeds the delegated maximum (${del.scope.max_ttl_seconds}s)`;
    if (!verifyB64(publicFromHex(del.issuer_public_hex), grantApprovalString(grantDigest(g)), a.issuer_signature)) return "issuer signature over the grant is invalid";
    return null;
  }

  async sign(req: SignRequest): Promise<SignResult> {
    const grants = req.grants ?? [];
    const targets = normalizeTargets(req.targets);
    const digest = sha256hex(canonicalJson({ source: req.source, grants, revision: req.revision, platforms: req.platforms, rollbackOf: req.rollbackOf ?? null, ...(Object.keys(targets).length ? { targets } : {}) }));
    if (req.publicationId) {
      const seen = this.state.journal!.find((j) => j.id === req.publicationId);
      if (seen) {
        if (seen.digest !== digest) throw new SignerError(409, `publication ${req.publicationId} was already signed with different content`);
        return seen.result;
      }
    }
    if (req.revision <= this.state.last_revision) throw new SignerError(409, `revision ${req.revision} is not newer than ${this.state.last_revision}`);
    const now = req.issuedAt.getTime();
    const baseDigest = policyDigest(await this.normalize(req.source));

    // ---- base policy: structured semantic diff against the last base this signer signed
    const needsOwner: string[] = [];
    if (this.state.last_source === null) needsOwner.push("first policy for this signer");
    else {
      const d = await this.moatctl.diff(this.state.last_source, req.source);
      const changes = d.diff.changes;
      if (!Array.isArray(changes)) throw new SignerError(500, "moatctl diff returned no structured diff.changes[]; refusing to decide from text");
      for (const c of changes as SemanticChange[]) {
        if (c.direction === "broadening") needsOwner.push(`${c.kind} ${c.item}`);
        else if (c.direction !== "narrowing" && c.direction !== "neutral") throw new SignerError(500, `unknown change direction ${String(c.direction)} for ${c.item}; refusing`);
      }
    }

    // ---- grants: exact moat.grant.v1 overlays compared by id and authority digest
    const prev = this.state.last_grants!;
    const seen = new Set<string>();
    const fresh: GrantV1[] = [];
    for (const g of grants) {
      if (seen.has(g.grant_id)) throw new SignerError(422, `grant ${g.grant_id} appears twice`);
      seen.add(g.grant_id);
      const bad = grantProblem(g, baseDigest);
      if (bad) throw new SignerError(bad.startsWith("approved against") ? 409 : 422, `grant ${g.grant_id}: ${bad}`);
      if (prev[g.grant_id] !== undefined) {
        if (prev[g.grant_id] !== authorityDigest(g)) throw new SignerError(409, `grant ${g.grant_id} was signed before with different content; a grant id is never reused`);
        continue;
      }
      if (this.state.retired![g.grant_id]) throw new SignerError(409, `grant ${g.grant_id} was removed before its deadline and cannot be re-added`);
      fresh.push(g);
    }
    const why: string[] = [];
    let attested = 0;
    let delegated = 0;
    const issuers = new Set<string>();
    for (const g of fresh) {
      if (Math.abs(Date.parse(g.issued_at) - now) > CLOCK_SKEW_MS) {
        why.push(`${g.grant_id}: issue time is not current`);
        continue;
      }
      if (!(Date.parse(g.admission_until) > now)) {
        why.push(`${g.grant_id}: already past its deadline`);
        continue;
      }
      const approval = (req.grantApprovals ?? []).find((a) => a.grant_id === g.grant_id);
      if (approval) {
        const bad = this.checkApproval(g, approval, req.issuedAt);
        if (bad) why.push(`${g.grant_id}: ${bad}`);
        else (delegated++, issuers.add(approval.delegation.issuer_key_id));
      } else if (g.issuer.role === "owner" && req.ownerSessionAttested && this.controllerAttestedGrants) attested++;
      else why.push(`${g.grant_id}: needs a delegated issuer's signature over the exact grant${this.controllerAttestedGrants ? " or an authenticated owner session" : ""}`);
    }
    if (why.length) throw new SignerError(403, `refusing to sign new temporary grant(s): ${why.join("; ")}`);

    let authorizedBy: AuthorizedBy = fresh.length === 0 ? "narrowing" : delegated > 0 && attested === 0 ? "delegated_issuer" : "temporary_grant_overlay";
    if (needsOwner.length) {
      const owner = req.ownerAuthorization ? this.checkOwner(req.subject, req.source, req.ownerAuthorization) : false;
      if (!owner) throw new SignerError(403, `broadening change (${needsOwner.join("; ")}) needs a local owner authorization signed with an owner key`);
      authorizedBy = "owner_key";
    }

    const snapshots: SignResult["snapshots"] = [];
    let effectiveDigest: string | null = null;
    for (const p of req.platforms) {
      const devs = targets[p] ?? [];
      const c = await this.moatctl.compile(req.source, p, req.revision, req.issuedAt, req.rollbackOf ?? null, grants, devs);
      if (!c.ok) throw new SignerError(422, `does not compile for ${p}${devs.length ? ` (devices ${devs.join(", ")})` : ""}: ${c.error}`);
      const report = (JSON.parse(c.snapshot) as { report: { effective_digest?: string | null } }).report;
      effectiveDigest ??= report.effective_digest ?? null;
      snapshots.push({ platform: p, signed: signSnapshotBytes(this.kp, c.snapshot), report });
    }
    const broadening = [...needsOwner, ...fresh.map((g) => `new temporary grant ${g.grant_id}`)];
    const result: SignResult = { revision: req.revision, publication_id: req.publicationId ?? null, snapshots, broadening, authorizedBy, ...(issuers.size ? { issuers: [...issuers] } : {}), grants: grants.map((g) => g.grant_id), effective_digest: effectiveDigest };
    const nextGrants: Record<string, string> = Object.fromEntries(grants.map((g) => [g.grant_id, authorityDigest(g)]));
    const retired = { ...this.state.retired! };
    for (const [gid] of Object.entries(prev)) if (!(gid in nextGrants)) retired[gid] = String(req.issuedAt.toISOString());
    // keep a removed grant's id only while it could still have been valid (24 h bounds every grant)
    for (const [gid, at] of Object.entries(retired)) if (now - Date.parse(at) > MAX_GRANT_SECONDS * 1000 + CLOCK_SKEW_MS) delete retired[gid];
    this.state = { last_revision: req.revision, last_source: req.source, last_grants: nextGrants, retired, journal: [...(this.state.journal ?? []), ...(req.publicationId ? [{ id: req.publicationId, revision: req.revision, digest, result }] : [])].slice(-JOURNAL_KEEP) };
    // durable before the reply leaves: a lost reply is recovered from this journal, never re-signed differently
    this.save();
    return result;
  }

  private checkOwner(subject: string, source: string, a: OwnerAuthorization): boolean {
    const hex = this.ownerKeys.get(a.key_id);
    if (!hex) return false;
    return verifyB64(publicFromHex(hex), ownerAuthorizationString(subject, sha256hex(source)), a.signature);
  }
}

/** Sorted, de-duplicated device lists per platform; platforms with no devices are dropped (fleet-wide compile). */
export function normalizeTargets(t: SignRequest["targets"]): Partial<Record<"linux" | "macos" | "dns", string[]>> {
  const out: Partial<Record<"linux" | "macos" | "dns", string[]>> = {};
  for (const p of ["dns", "linux", "macos"] as const) {
    const v = t?.[p];
    if (!Array.isArray(v)) continue;
    const list = [...new Set(v.map(String))].sort();
    for (const d of list) if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(d)) throw new SignerError(422, `target device id ${JSON.stringify(d)} is not a device id`);
    if (list.length) out[p] = list;
  }
  return out;
}
