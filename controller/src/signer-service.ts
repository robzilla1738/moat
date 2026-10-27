/**
 * `moat-signer serve`: the signer as its own process and OS identity, reachable only over a Unix socket whose
 * permissions admit the controller's group. The controller holds no signing key. The socket accepts one typed
 * operation (`sign`) and returns signed snapshots or a refusal; there is no remote shell and no key export.
 */
import { createServer, request, type Server } from "node:http";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import type { SignRequest, SignResult } from "./signer.ts";
import { Signer, SignerError } from "./signer.ts";
import type { SignerLike } from "./controller.ts";

export function serveSigner(signer: Signer, socketPath: string): Server {
  if (existsSync(socketPath)) unlinkSync(socketPath);
  const srv = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const send = (status: number, v: unknown) => (res.writeHead(status, { "content-type": "application/json" }), res.end(JSON.stringify(v)));
    if (req.method === "GET" && req.url === "/identity") return send(200, { key_id: signer.keyId, public_hex: signer.publicHex, last_revision: signer.lastRevision });
    if (req.method !== "POST" || req.url !== "/sign") return send(404, { error: "not found" });
    try {
      const b = JSON.parse(Buffer.concat(chunks).toString("utf8")) as SignRequest & { issuedAt: string };
      send(200, await signer.sign({ ...b, issuedAt: new Date(b.issuedAt) }));
    } catch (e) {
      send(e instanceof SignerError ? e.status : 500, { error: (e as Error).message });
    }
  });
  srv.listen(socketPath, () => chmodSync(socketPath, 0o660));
  return srv;
}

function call(socketPath: string, method: string, path: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? "" : JSON.stringify(body);
    const req = request({ socketPath, method, path, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c as Buffer));
      res.on("end", () => resolve({ status: res.statusCode ?? 500, json: JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, unknown> }));
    });
    req.on("error", reject);
    req.end(data);
  });
}

export async function signerClient(socketPath: string): Promise<SignerLike> {
  const id = await call(socketPath, "GET", "/identity");
  return {
    keyId: String(id.json.key_id),
    publicHex: String(id.json.public_hex),
    async sign(r) {
      const out = await call(socketPath, "POST", "/sign", { ...r, issuedAt: r.issuedAt.toISOString() });
      if (out.status !== 200) throw new SignerError(out.status, String(out.json.error ?? "signer refused"));
      return out.json as unknown as SignResult;
    },
  };
}
