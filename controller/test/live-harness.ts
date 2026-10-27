/**
 * A real controller for browser integration tests: separate signer object with real owner keys, Rust moatctl for
 * validation/compilation/signing input, the real HTTP server serving the built web UI, and an enrolled endpoint
 * that talks to it only through device-signed HTTP requests. Nothing here stubs a controller answer.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { Controller } from "../src/controller.ts";
import { generateKeyPair } from "../src/crypto.ts";
import { Moatctl } from "../src/moatctl.ts";
import { Signer } from "../src/signer.ts";
import { startServer } from "../src/server.ts";
import { enroll, signedPost, type AgentState } from "../src/agent.ts";
import { authorize, HOME, MOATCTL } from "./helpers.ts";

export interface Harness {
  url: string;
  c: Controller;
  ownerToken: string;
  viewerToken: string;
  device: AgentState;
  /** One device sync over HTTP, signed with the device key; returns the controller's (verified) answer. */
  sync(body: Record<string, unknown>): Promise<Record<string, unknown>>;
  owner(method: string, path: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> }>;
  stop(): Promise<void>;
}

export async function startHarness(webDir: string): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "moat-live-"));
  const moatctl = new Moatctl(MOATCTL);
  const owner = generateKeyPair();
  const signer = new Signer({ seedHex: generateKeyPair().seedHex, ownerPublicKeysHex: [owner.publicHex], moatctl, statePath: join(dir, "signer.json") });
  const c = new Controller({ dataDir: join(dir, "data"), signer, moatctl, publicUrl: "https://moat.test" });
  const ownerToken = c.createToken("robert", "owner").token;
  const viewerToken = c.createToken("tv", "viewer").token;
  const srv = startServer(c, { host: "127.0.0.1", port: 0, webDir });
  await new Promise((r) => srv.once("listening", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const f = (u: string, i: { method: string; headers: Record<string, string>; body: string }) => fetch(u, i) as never;
  const ownerCall = async (method: string, path: string, body?: unknown) => {
    const r = await fetch(url + path, { method, headers: { "content-type": "application/json", authorization: `Bearer ${ownerToken}` }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, json: (await r.json()) as Record<string, unknown> };
  };
  // the first policy, authorized with the owner key (never by the browser)
  const prop = (await ownerCall("POST", "/v1/policy/proposals", { source: HOME, message: "initial policy" })).json as { id: string; authorization_digest: string };
  const ap = await ownerCall("POST", `/v1/policy/proposals/${prop.id}/approve`, { owner_authorization: authorize(owner, prop.id, prop.authorization_digest) });
  if (ap.status !== 200) throw new Error(`bootstrap failed: ${JSON.stringify(ap.json)}`);
  const code = (await ownerCall("POST", "/v1/enrollment-codes", {})).json as { code: string };
  const device = await enroll(url, code.code, "omarchy", "linux", f, { capabilities: { session_enforcement: { support: "supported" } } });
  return {
    url,
    c,
    ownerToken,
    viewerToken,
    device,
    async sync(body) {
      const r = await signedPost(device, "/v1/device/sync", body, f);
      if (r.status !== 200) throw new Error(`sync ${r.status}: ${JSON.stringify(r.json)}`);
      return r.json;
    },
    owner: ownerCall,
    stop: () => new Promise((r) => srv.close(() => r())),
  };
}
