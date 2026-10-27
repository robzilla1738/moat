/**
 * The policy signer: a separate identity from the controller.
 *
 * It holds the snapshot signing key and its own list of owner public keys (a file the controller cannot write in a
 * real deployment: run it as the `moat-signer` user with `moat-signer serve`). It never signs bytes the controller
 * hands it. It receives policy *source*, compiles it itself with moatctl, compares it with the last source *it*
 * signed, and decides:
 *
 *   - narrowing or neutral change ................. sign ("narrowing")
 *   - broadening where every broadening item is an exact temporary grant: an override-layer allow, owner_action
 *     provenance, expiring within MAX_GRANT_SECONDS, one address or hostname, one port, scoped to exactly one device
 *     (a reserved `moat-grant-*` device group with one member) and one session/task or one app executable, and
 *       * a delegated issuer (a phone) signed the exact grant plan, within the scope the owner key delegated to it
 *         ........................................................................ sign ("delegated_issuer")
 *       * or, only when this signer was started with controller-attested grants enabled, the controller attests
 *         that an authenticated owner session asked .......................... sign ("temporary_grant_overlay")
 *   - any other broadening ......................... only with a valid owner-key signature over the exact source
 *
 * Every signature is journaled by publication id before it is returned, so a controller that lost the reply can
 * recover the same revision instead of minting a conflicting one.
 */
import { existsSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { canonicalJson, delegationString, grantApprovalString, keyPairFromSeed, ownerAuthorizationString, publicFromHex, keyIdOf, sha256hex, signSnapshotBytes, verifyB64, type KeyPair, type SignedSnapshot } from "./crypto.ts";
import type { Moatctl } from "./moatctl.ts";

export const MAX_GRANT_SECONDS = 24 * 3600;
export const GRANT_GROUP_PREFIX = "moat-grant-";
const JOURNAL_KEEP = 64;

export interface OwnerAuthorization { key_id: string; signature: string }

/** The exact grant a person approved (a `moat.grant.v1` record without issuer signature fields). */
export interface GrantPlan {
  schema: "moat.grant.v1";
  grant_id: string;
  idempotency_key: string;
  kind: "allow_once" | "temporary";
  scope: { kind: "task"; device_id: string; boot_id?: string | null; task_id: string } | { kind: "app_on_device"; device_id: string; executable: { path: string } };
  destination: { kind: "address"; address: string } | { kind: "hostname"; hostname: string };
  transport: "tcp" | "udp";
  port: number;
  issued_at: string;
  not_before: string;
  admission_until: string;
  stream_policy: "admission_only";
  base_policy_digest: string;
  incident: { id: string; revision: number } | null;
  reason: string;
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

export interface GrantApproval { plan: GrantPlan; delegation: Delegation; issuer_signature: string }

export interface SignRequest {
  /** Journal key: the same publication id always yields the same signed revision. */
  publicationId?: string;
  /** Proposal or grant id the owner authorized (bound into the authorization). */
  subject: string;
  source: string;
  revision: number;
  rollbackOf?: number | null;
  platforms: ("linux" | "macos" | "dns")[];
  ownerAuthorization?: OwnerAuthorization | null;
  /** Controller attestation that an authenticated owner session requested a temporary grant (only honored when enabled). */
  ownerSessionAttested?: boolean;
  /** Delegated-issuer approvals of exact grant plans, one per new grant rule. */
  grantApprovals?: GrantApproval[];
  issuedAt: Date;
}
export type AuthorizedBy = "narrowing" | "temporary_grant_overlay" | "delegated_issuer" | "owner_key";
export interface SignResult { revision: number; publication_id: string | null; snapshots: { platform: string; signed: SignedSnapshot; report: unknown }[]; broadening: string[]; authorizedBy: AuthorizedBy; issuers?: string[] }

interface JournalEntry { id: string; revision: number; digest: string; result: SignResult }
interface SignerState { last_revision: number; last_source: string | null; journal?: JournalEntry[] }

interface RuleJson {
  id: string;
  action: string;
  layer?: string;
  expires_at?: string;
  transport?: string;
  ports?: unknown[];
  selector?: { apps?: { executable?: string }[]; device_groups?: string[]; users?: unknown[]; ancestors?: unknown[]; session?: { profiles?: string[]; session_ids?: string[]; any_protected?: boolean } };
  destinations: { hosts?: string[]; cidrs?: string[]; scopes?: unknown[]; sets?: unknown[]; providers?: unknown[]; any?: boolean };
  provenance: { kind: string; audit_ref?: string };
}
interface PolicyJson { rules: RuleJson[]; device_groups?: Record<string, string[]> }

export class SignerError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function planDigest(plan: GrantPlan): string {
  return `sha256:${sha256hex(canonicalJson(plan))}`;
}

const sameSet = (a: string[] = [], b: string[] = []) => a.length === b.length && [...a].sort().join("\u0000") === [...b].sort().join("\u0000");

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

  private async normalize(source: string): Promise<PolicyJson> {
    const r = await this.moatctl.run(["normalize", "@p.toml"], { "p.toml": source });
    if (r.code !== 0) throw new SignerError(422, `policy invalid: ${(r.stderr || r.stdout).trim()}`);
    return JSON.parse(r.stdout) as PolicyJson;
  }

  /** Is this added rule a bounded temporary grant (before device/authority checks)? */
  static boundedGrant(r: RuleJson, now: Date): string | null {
    if (r.action !== "allow") return "not an allow";
    if (r.layer !== "override") return "not in the override layer";
    if (r.provenance.kind !== "owner_action" || !r.provenance.audit_ref) return "missing owner_action provenance with an audit record";
    if (!r.expires_at) return "does not expire";
    const ttl = (Date.parse(r.expires_at) - now.getTime()) / 1000;
    if (!(ttl > 0 && ttl <= MAX_GRANT_SECONDS)) return `expiry must be within ${MAX_GRANT_SECONDS / 3600}h`;
    const narrow = (r.selector?.apps?.length ?? 0) > 0 || !!r.selector?.session;
    if (!narrow) return "not scoped to an app or session";
    if (r.selector?.session?.any_protected) return "scoped to every protected session";
    if (r.selector?.session && !(r.selector.session.session_ids?.length === 1)) return "a session grant must name exactly one session";
    if ((r.selector?.apps?.length ?? 0) > 1) return "an app grant must name exactly one executable";
    if (r.selector?.users?.length || r.selector?.ancestors?.length) return "user/ancestor selectors are not temporary-grant material";
    const d = r.destinations;
    const single = (d.hosts?.length ?? 0) + (d.cidrs?.length ?? 0) === 1 && !d.any && !d.scopes?.length && !d.sets?.length && !d.providers?.length;
    if (!single) return "must name exactly one host or address";
    const c = d.cidrs?.[0];
    if (c && !(c.endsWith("/32") || c.endsWith("/128"))) return "address grants must be a single address";
    if (d.hosts?.[0]?.startsWith("*")) return "wildcard hosts are not temporary-grant material";
    if (!r.ports || r.ports.length !== 1 || typeof r.ports[0] !== "number") return "must name exactly one port";
    return null;
  }

  /** Device scope: exactly one reserved grant group with exactly one member. Returns the device id or a reason. */
  static grantDevice(r: RuleJson, p: PolicyJson): { device: string } | { error: string } {
    const groups = r.selector?.device_groups ?? [];
    if (groups.length !== 1 || !groups[0]!.startsWith(GRANT_GROUP_PREFIX)) return { error: "not scoped to exactly one device (reserved moat-grant-* group)" };
    const members = p.device_groups?.[groups[0]!] ?? [];
    if (members.length !== 1) return { error: `device group ${groups[0]} must have exactly one member` };
    return { device: members[0]! };
  }

  /** Does a delegated-issuer approval authorize exactly this rule? */
  private checkApproval(r: RuleJson, device: string, a: GrantApproval, issuedAt: Date): string | null {
    const plan = a.plan;
    const del = a.delegation;
    if (plan.grant_id !== r.id) return "plan names a different grant";
    if (plan.scope.device_id !== device) return "plan names a different device";
    if (plan.scope.kind === "task") {
      if (!sameSet(r.selector?.session?.session_ids, [plan.scope.task_id]) || r.selector?.apps?.length) return "rule scope differs from the approved task";
    } else if (plan.scope.kind === "app_on_device") {
      if (r.selector?.session || r.selector?.apps?.length !== 1 || r.selector.apps[0]!.executable !== plan.scope.executable.path) return "rule scope differs from the approved app";
    } else return "unsupported plan scope";
    const want = plan.destination.kind === "address" ? { cidrs: [`${plan.destination.address}/${plan.destination.address.includes(":") ? 128 : 32}`] } : { hosts: [plan.destination.hostname] };
    if (!sameSet(r.destinations.cidrs, want.cidrs) || !sameSet(r.destinations.hosts, want.hosts)) return "rule destination differs from the approved plan";
    if ((r.transport ?? "tcp") !== plan.transport || r.ports?.[0] !== plan.port) return "rule transport/port differs from the approved plan";
    if (!r.expires_at || Date.parse(r.expires_at) !== Date.parse(plan.admission_until)) return "rule expiry differs from the approved plan";
    // the delegation itself
    const ownerHex = this.ownerKeys.get(del.owner_key_id);
    if (!ownerHex) return "delegation is not signed by a trusted owner key";
    const { signature, ...body } = del;
    if (!verifyB64(publicFromHex(ownerHex), delegationString(body), signature)) return "delegation signature invalid";
    if (keyIdOf(del.issuer_public_hex) !== del.issuer_key_id) return "delegation issuer key id mismatch";
    if (!(Date.parse(del.not_after) > issuedAt.getTime())) return "delegation expired";
    if (!del.scope.kinds.includes(plan.kind)) return `delegation does not cover ${plan.kind}`;
    if (!del.scope.devices.includes(plan.scope.device_id)) return `delegation does not cover device ${plan.scope.device_id}`;
    const ttl = (Date.parse(plan.admission_until) - Date.parse(plan.issued_at)) / 1000;
    if (!(ttl > 0 && ttl <= Math.min(del.scope.max_ttl_seconds, MAX_GRANT_SECONDS))) return `lifetime exceeds the delegated maximum (${del.scope.max_ttl_seconds}s)`;
    if (Math.abs(Date.parse(plan.issued_at) - issuedAt.getTime()) > 15 * 60_000) return "plan issue time is not current";
    if (!verifyB64(publicFromHex(del.issuer_public_hex), grantApprovalString(planDigest(plan)), a.issuer_signature)) return "issuer signature over the plan is invalid";
    return null;
  }

  async sign(req: SignRequest): Promise<SignResult> {
    const digest = sha256hex(canonicalJson({ source: req.source, revision: req.revision, platforms: req.platforms, rollbackOf: req.rollbackOf ?? null }));
    if (req.publicationId) {
      const seen = this.state.journal!.find((j) => j.id === req.publicationId);
      if (seen) {
        if (seen.digest !== digest) throw new SignerError(409, `publication ${req.publicationId} was already signed with different content`);
        return seen.result;
      }
    }
    if (req.revision <= this.state.last_revision) throw new SignerError(409, `revision ${req.revision} is not newer than ${this.state.last_revision}`);
    const proposed = await this.normalize(req.source);
    let broadening: string[] = [];
    let addedRuleIds: string[] = [];
    let previous: PolicyJson | null = null;
    if (this.state.last_source === null) {
      broadening = ["first policy for this signer"];
    } else {
      const d = await this.moatctl.diff(this.state.last_source, req.source);
      broadening = ((d.diff.broadening as string[] | undefined) ?? []).slice();
      addedRuleIds = (d.diff.added as string[] | undefined) ?? [];
      previous = await this.normalize(this.state.last_source);
    }
    let authorizedBy: AuthorizedBy = "narrowing";
    const issuers = new Set<string>();
    if (broadening.length) {
      const owner = req.ownerAuthorization ? this.checkOwner(req.subject, req.source, req.ownerAuthorization) : false;
      if (owner) authorizedBy = "owner_key";
      else {
        const why: string[] = [];
        const grantIds: string[] = [];
        for (const b of broadening) {
          if (b.startsWith("new allow rule ")) grantIds.push(b.slice("new allow rule ".length));
          else if (!/^device group/i.test(b)) why.push(`not only new grant rules (${b})`);
        }
        if (!previous) why.push("no previously signed policy to compare against");
        let attested = 0;
        let delegated = 0;
        for (const gid of grantIds) {
          const r = proposed.rules.find((x) => x.id === gid);
          if (!r || !addedRuleIds.includes(gid)) {
            why.push(`${gid}: unknown rule`);
            continue;
          }
          const bounded = Signer.boundedGrant(r, req.issuedAt);
          if (bounded) {
            why.push(`${gid}: ${bounded}`);
            continue;
          }
          const dev = Signer.grantDevice(r, proposed);
          if ("error" in dev) {
            why.push(`${gid}: ${dev.error}`);
            continue;
          }
          const approval = (req.grantApprovals ?? []).find((a) => a.plan.grant_id === gid);
          if (approval) {
            const bad = this.checkApproval(r, dev.device, approval, req.issuedAt);
            if (bad) why.push(`${gid}: ${bad}`);
            else (delegated++, issuers.add(approval.delegation.issuer_key_id));
          } else if (req.ownerSessionAttested && this.controllerAttestedGrants) attested++;
          else why.push(`${gid}: needs a delegated issuer's signature over the exact grant${this.controllerAttestedGrants ? " or an authenticated owner session" : ""}`);
        }
        // device groups: only reserved one-member grant groups may appear or change, and only for the new grant rules
        if (previous) {
          const before = previous.device_groups ?? {};
          const after = proposed.device_groups ?? {};
          for (const [g, members] of Object.entries(after)) {
            if (sameSet(before[g], members) && g in before) continue;
            if (!g.startsWith(GRANT_GROUP_PREFIX)) {
              why.push(`device group ${g} changed`);
              continue;
            }
            const users = proposed.rules.filter((x) => x.selector?.device_groups?.includes(g));
            if (members.length !== 1 || users.some((u) => !grantIds.includes(u.id) || u.selector!.device_groups!.length !== 1)) why.push(`device group ${g} is not a one-device group used only by new grants`);
          }
        }
        if (why.length || (grantIds.length > 0 && attested + delegated === 0)) {
          throw new SignerError(403, `broadening change (${broadening.join("; ")}) needs a local owner authorization signed with an owner key${why.length ? `; not an exact temporary grant: ${why.join("; ")}` : ""}`);
        }
        // only reserved grant groups disappeared (expired/revoked grants): that removes authority
        authorizedBy = grantIds.length === 0 ? "narrowing" : delegated > 0 && attested === 0 ? "delegated_issuer" : "temporary_grant_overlay";
      }
    }
    const snapshots: SignResult["snapshots"] = [];
    for (const p of req.platforms) {
      const c = await this.moatctl.compile(req.source, p, req.revision, req.issuedAt, req.rollbackOf ?? null);
      if (!c.ok) throw new SignerError(422, `does not compile for ${p}: ${c.error}`);
      const report = (JSON.parse(c.snapshot) as { report: unknown }).report;
      snapshots.push({ platform: p, signed: signSnapshotBytes(this.kp, c.snapshot), report });
    }
    const result: SignResult = { revision: req.revision, publication_id: req.publicationId ?? null, snapshots, broadening, authorizedBy, ...(issuers.size ? { issuers: [...issuers] } : {}) };
    this.state = { last_revision: req.revision, last_source: req.source, journal: [...(this.state.journal ?? []), ...(req.publicationId ? [{ id: req.publicationId, revision: req.revision, digest, result }] : [])].slice(-JOURNAL_KEEP) };
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
