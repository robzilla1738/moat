/**
 * This browser as a narrowly delegated approver ("phone approvals", roadmap 6.4).
 *
 * The browser holds its own Ed25519 key, never the owner key. The owner delegates a bounded scope to it off the page
 * (`moat-controller delegate-issuer`: named devices, allow-once only, a maximum lifetime, an expiry). The signer
 * verifies that delegation and the browser's signature over the exact grant plan on every use, so a stolen browser
 * key or a compromised controller cannot exceed the delegated scope.
 */
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export const ISSUER_KEY = "moat.issuer";

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
export interface IssuerState { seedHex: string; publicHex: string; keyId: string; delegation: Delegation | null }

export const keyIdOf = (publicHex: string) => bytesToHex(sha256(hexToBytes(publicHex))).slice(0, 16);

export function newIssuer(seed: Uint8Array = ed.utils.randomPrivateKey()): IssuerState {
  const publicHex = bytesToHex(ed.getPublicKey(seed));
  return { seedHex: bytesToHex(seed), publicHex, keyId: keyIdOf(publicHex), delegation: null };
}

/** The exact string the signer verifies (crypto.ts grantApprovalString). */
export const approvalString = (digest: string) => `moat-grant-approval-v1\n${digest}\n`;

export function signApproval(st: IssuerState, digest: string): string {
  const sig = ed.sign(utf8ToBytes(approvalString(digest)), hexToBytes(st.seedHex));
  let bin = "";
  for (const b of sig) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function loadIssuer(): IssuerState | null {
  if (typeof localStorage === "undefined") return null;
  try {
    const v = localStorage.getItem(ISSUER_KEY);
    return v ? (JSON.parse(v) as IssuerState) : null;
  } catch {
    return null;
  }
}
export function saveIssuer(st: IssuerState | null) {
  if (st) localStorage.setItem(ISSUER_KEY, JSON.stringify(st));
  else localStorage.removeItem(ISSUER_KEY);
}

/** Why a delegation cannot be used by this browser, or null. Checked locally for clear errors; the signer decides. */
export function delegationProblem(st: IssuerState, d: unknown, now = Date.now()): string | null {
  const x = d as Partial<Delegation> | null;
  if (!x || x.schema !== "moat.delegation.v1") return "Not a moat.delegation.v1 object.";
  if (x.issuer_public_hex !== st.publicHex || x.issuer_key_id !== st.keyId) return "This delegation was made for a different key, not this browser.";
  if (!x.scope || !Array.isArray(x.scope.devices) || !x.scope.devices.length) return "The delegation names no devices.";
  if (!(Date.parse(String(x.not_after)) > now)) return "The delegation has expired.";
  if (typeof x.signature !== "string" || typeof x.owner_key_id !== "string") return "The delegation is not signed.";
  return null;
}
