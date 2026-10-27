/**
 * Ed25519 helpers compatible with moat-core (`core/moat-core/src/signing.rs`):
 *  - key files are 32-byte seeds / public keys as hex (what `moatctl keygen` writes);
 *  - key_id = first 16 hex chars of sha256(raw public key);
 *  - a signed snapshot's payload is base64 of the exact signed JSON bytes.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from "node:crypto";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface KeyPair { privateKey: KeyObject; publicKey: KeyObject; publicHex: string; keyId: string; seedHex: string }

export function sha256hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function privateFromSeedHex(hex: string): KeyObject {
  const seed = Buffer.from(hex.trim(), "hex");
  if (seed.length !== 32) throw new Error("signing key must be 32 bytes of hex");
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
}

export function publicFromHex(hex: string): KeyObject {
  const raw = Buffer.from(hex.trim(), "hex");
  if (raw.length !== 32) throw new Error("public key must be 32 bytes of hex");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

export function rawPublicHex(pub: KeyObject): string {
  const der = pub.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32)).toString("hex");
}

export function keyIdOf(publicHex: string): string {
  return sha256hex(Buffer.from(publicHex, "hex")).slice(0, 16);
}

export function keyPairFromSeed(seedHex: string): KeyPair {
  const privateKey = privateFromSeedHex(seedHex);
  const publicKey = createPublicKey(privateKey);
  const publicHex = rawPublicHex(publicKey);
  return { privateKey, publicKey, publicHex, keyId: keyIdOf(publicHex), seedHex: seedHex.trim() };
}

export function generateKeyPair(): KeyPair {
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  return keyPairFromSeed(Buffer.from(der.subarray(der.length - 32)).toString("hex"));
}

export function signB64(key: KeyObject, data: Buffer | string): string {
  return sign(null, typeof data === "string" ? Buffer.from(data) : data, key).toString("base64");
}

export function verifyB64(pub: KeyObject, data: Buffer | string, sigB64: string): boolean {
  try {
    return verify(null, typeof data === "string" ? Buffer.from(data) : data, pub, Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

export function token(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function id(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

/** SignedSnapshot exactly as moat-core expects it. */
export interface SignedSnapshot { schema: "moat.signed_snapshot.v1"; key_id: string; payload: string; signature: string }

export function signSnapshotBytes(kp: KeyPair, snapshotJson: string): SignedSnapshot {
  const bytes = Buffer.from(snapshotJson, "utf8");
  return { schema: "moat.signed_snapshot.v1", key_id: kp.keyId, payload: bytes.toString("base64"), signature: signB64(kp.privateKey, bytes) };
}

/**
 * Mutual request authentication (independent of Tailscale or TLS):
 *   request:  sig_device(method \n path \n ts \n nonce \n sha256(body))
 *   response: sig_controller("response" \n status \n ts \n nonce \n sha256(body))
 * The nonce is echoed so a response cannot be replayed for another request.
 */
export function requestString(method: string, path: string, ts: string, nonce: string, body: string): string {
  return `moat.req.v1\n${method.toUpperCase()}\n${path}\n${ts}\n${nonce}\n${sha256hex(body)}`;
}
export function responseString(status: number, ts: string, nonce: string, body: string): string {
  return `moat.resp.v1\n${status}\n${ts}\n${nonce}\n${sha256hex(body)}`;
}

/** What a local owner signs to authorize a permission-broadening change. */
export function ownerAuthorizationString(subject: string, digest: string): string {
  return `moat.owner_authorization.v1\n${subject}\n${digest}`;
}

/** Canonical JSON for digests: object keys sorted, no insignificant whitespace, no undefined values. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? "null" : canonicalJson(x))).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
    .join(",")}}`;
}

/** What a delegated issuer (e.g. a phone) signs: the digest of the exact grant plan it was shown. */
export function grantApprovalString(planDigest: string): string {
  return `moat-grant-approval-v1\n${planDigest}\n`;
}

/** What the owner key signs to delegate a bounded approval scope to another key. */
export function delegationString(body: unknown): string {
  return `moat-delegation-v1\n${canonicalJson(body)}\n`;
}
