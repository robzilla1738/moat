import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Controller } from "../src/controller.ts";
import { generateKeyPair, ownerAuthorizationString, signB64, type KeyPair } from "../src/crypto.ts";
import { Moatctl } from "../src/moatctl.ts";
import { Signer } from "../src/signer.ts";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const candidates = [process.env.MOATCTL, join(ROOT, "target/debug/moatctl"), "/tmp/moat-target/debug/moatctl"].filter(Boolean) as string[];
export const MOATCTL = candidates.find((c) => existsSync(c));
if (!MOATCTL) throw new Error("moatctl binary not found: run `cargo build -p moatctl` (or set MOATCTL)");

export const HOME = readFileSync(join(ROOT, "conformance/policies/home.toml"), "utf8");

export interface Fixture { c: Controller; signer: Signer; signerKey: KeyPair; owner: KeyPair; ownerToken: string; moatctl: Moatctl; clock: { t: number } }

export function fixture(start = "2026-10-26T12:00:00Z", opts: { controllerAttestedGrants?: boolean } = {}): Fixture {
  const moatctl = new Moatctl(MOATCTL);
  const signerKey = generateKeyPair();
  const owner = generateKeyPair();
  const signer = new Signer({ seedHex: signerKey.seedHex, ownerPublicKeysHex: [owner.publicHex], moatctl, controllerAttestedGrants: opts.controllerAttestedGrants ?? true });
  const clock = { t: Date.parse(start) };
  const c = new Controller({ dataDir: ":memory:", signer, moatctl, now: () => new Date(clock.t) });
  const ownerToken = c.createToken("robert", "owner").token;
  return { c, signer, signerKey, owner, ownerToken, moatctl, clock };
}

export function authorize(owner: KeyPair, subject: string, digest: string) {
  return { key_id: owner.keyId, signature: signB64(owner.privateKey, ownerAuthorizationString(subject, digest)) };
}

/** Propose + owner-authorize + approve the home policy; returns the revision. */
export async function bootstrap(f: Fixture, source = HOME) {
  const p = f.c.authenticate(f.ownerToken)!;
  const prop = (await f.c.propose(p, source, "initial")) as { id: string; authorization_digest: string };
  return f.c.approve(p, prop.id, authorize(f.owner, prop.id, prop.authorization_digest));
}
