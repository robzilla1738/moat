/**
 * The policy signer: a separate identity from the controller.
 *
 * It holds the snapshot signing key and its own list of owner public keys (a file the controller cannot write in a
 * real deployment: run it as the `moat-signer` user with `moat-signer serve`). It never signs bytes the controller
 * hands it. It receives policy *source*, compiles it itself with moatctl, compares it with the last source *it*
 * signed, and decides:
 *
 *   - narrowing or neutral change ................. sign
 *   - broadening, and every broadening item is a bounded temporary grant (override layer, owner_action provenance,
 *     expiring within MAX_GRANT_SECONDS, scoped to an app or session, a single address or hostname) and the request
 *     carries the controller's attestation that an authenticated owner asked ......... sign (audited overlay path)
 *   - any other broadening ......................... only with a valid owner-key signature over the exact source
 *
 * A coding agent that can edit the policy repository or call the controller API therefore cannot authorize its own
 * access: it has neither the owner key nor an owner session.
 */
import { existsSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { keyPairFromSeed, ownerAuthorizationString, publicFromHex, keyIdOf, sha256hex, signSnapshotBytes, verifyB64, type KeyPair, type SignedSnapshot } from "./crypto.ts";
import type { Moatctl } from "./moatctl.ts";

export const MAX_GRANT_SECONDS = 24 * 3600;

export interface OwnerAuthorization { key_id: string; signature: string }
export interface SignRequest {
  /** Proposal or grant id the owner authorized (bound into the authorization). */
  subject: string;
  source: string;
  revision: number;
  rollbackOf?: number | null;
  platforms: ("linux" | "macos" | "dns")[];
  ownerAuthorization?: OwnerAuthorization | null;
  /** Controller attestation that an authenticated owner session requested a temporary grant. */
  ownerSessionAttested?: boolean;
  issuedAt: Date;
}
export interface SignResult { revision: number; snapshots: { platform: string; signed: SignedSnapshot; report: unknown }[]; broadening: string[]; authorizedBy: "narrowing" | "temporary_grant_overlay" | "owner_key" }

interface SignerState { last_revision: number; last_source: string | null }

interface RuleJson {
  id: string;
  action: string;
  layer?: string;
  expires_at?: string;
  selector?: { apps?: unknown[]; session?: { profiles?: string[]; session_ids?: string[]; any_protected?: boolean } };
  destinations: { hosts?: string[]; cidrs?: string[]; scopes?: unknown[]; sets?: unknown[]; providers?: unknown[]; any?: boolean };
  provenance: { kind: string; audit_ref?: string };
}

export class SignerError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class Signer {
  private kp: KeyPair;
  private ownerKeys: Map<string, string>;
  private state: SignerState;
  private statePath: string | null;
  private moatctl: Moatctl;
  constructor(opts: { seedHex: string; ownerPublicKeysHex: string[]; moatctl: Moatctl; statePath?: string | null }) {
    this.kp = keyPairFromSeed(opts.seedHex);
    this.ownerKeys = new Map(opts.ownerPublicKeysHex.map((h) => [keyIdOf(h.trim()), h.trim()]));
    this.moatctl = opts.moatctl;
    this.statePath = opts.statePath ?? null;
    this.state = this.statePath && existsSync(this.statePath) ? (JSON.parse(readFileSync(this.statePath, "utf8")) as SignerState) : { last_revision: 0, last_source: null };
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

  private save() {
    if (!this.statePath) return;
    writeFileSync(`${this.statePath}.tmp`, JSON.stringify(this.state));
    renameSync(`${this.statePath}.tmp`, this.statePath);
  }

  private async normalize(source: string): Promise<{ rules: RuleJson[] }> {
    const r = await this.moatctl.run(["normalize", "@p.toml"], { "p.toml": source });
    if (r.code !== 0) throw new SignerError(422, `policy invalid: ${(r.stderr || r.stdout).trim()}`);
    return JSON.parse(r.stdout) as { rules: RuleJson[] };
  }

  /** Is this added rule a bounded temporary grant the overlay path may sign without an owner key? */
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
    const d = r.destinations;
    const single = (d.hosts?.length ?? 0) + (d.cidrs?.length ?? 0) === 1 && !d.any && !(d.scopes?.length) && !(d.sets?.length) && !(d.providers?.length);
    if (!single) return "must name exactly one host or address";
    const c = d.cidrs?.[0];
    if (c && !(c.endsWith("/32") || c.endsWith("/128"))) return "address grants must be a single address";
    if (d.hosts?.[0]?.startsWith("*")) return "wildcard hosts are not temporary-grant material";
    return null;
  }

  async sign(req: SignRequest): Promise<SignResult> {
    if (req.revision <= this.state.last_revision) throw new SignerError(409, `revision ${req.revision} is not newer than ${this.state.last_revision}`);
    const proposed = await this.normalize(req.source);
    let broadening: string[] = [];
    let addedRuleIds: string[] = [];
    let onlyAdditions = true;
    if (this.state.last_source === null) {
      broadening = ["first policy for this signer"];
      onlyAdditions = false;
    } else {
      const d = await this.moatctl.diff(this.state.last_source, req.source);
      broadening = ((d.diff.broadening as string[] | undefined) ?? []).slice();
      addedRuleIds = (d.diff.added as string[] | undefined) ?? [];
      // every broadening reason must be "new allow rule <id>" for the overlay path to apply
      onlyAdditions = broadening.every((b) => b.startsWith("new allow rule "));
    }
    let authorizedBy: SignResult["authorizedBy"] = "narrowing";
    if (broadening.length) {
      const owner = req.ownerAuthorization ? this.checkOwner(req.subject, req.source, req.ownerAuthorization) : false;
      if (owner) authorizedBy = "owner_key";
      else {
        const broadIds = broadening.map((b) => b.replace("new allow rule ", ""));
        const reasons = onlyAdditions
          ? broadIds.map((id) => {
              const r = proposed.rules.find((x) => x.id === id);
              return r && addedRuleIds.includes(id) ? Signer.boundedGrant(r, req.issuedAt) : "unknown rule";
            })
          : ["not only new rules"];
        const allBounded = onlyAdditions && reasons.every((x) => x === null);
        if (allBounded && req.ownerSessionAttested) authorizedBy = "temporary_grant_overlay";
        else {
          const why = reasons.filter((x) => x !== null).join("; ");
          throw new SignerError(403, `broadening change (${broadening.join("; ")}) needs a local owner authorization signed with an owner key${why ? `; not a bounded temporary grant: ${why}` : ""}${allBounded && !req.ownerSessionAttested ? "; temporary grants need an authenticated owner session" : ""}`);
        }
      }
    }
    const snapshots: SignResult["snapshots"] = [];
    for (const p of req.platforms) {
      const c = await this.moatctl.compile(req.source, p, req.revision, req.issuedAt, req.rollbackOf ?? null);
      if (!c.ok) throw new SignerError(422, `does not compile for ${p}: ${c.error}`);
      const report = (JSON.parse(c.snapshot) as { report: unknown }).report;
      snapshots.push({ platform: p, signed: signSnapshotBytes(this.kp, c.snapshot), report });
    }
    this.state = { last_revision: req.revision, last_source: req.source };
    this.save();
    return { revision: req.revision, snapshots, broadening, authorizedBy };
  }

  private checkOwner(subject: string, source: string, a: OwnerAuthorization): boolean {
    const hex = this.ownerKeys.get(a.key_id);
    if (!hex) return false;
    return verifyB64(publicFromHex(hex), ownerAuthorizationString(subject, sha256hex(source)), a.signature);
  }
}
