#!/usr/bin/env node
/**
 * moat-controller CLI.
 *
 *   init <dir>                      create controller key, owner token, and print next steps
 *   owner-keygen <file>             generate an owner key (keep it on the owner's device, never in agent workspaces)
 *   owner-authorize <file> <subject> <digest>   sign a broadening authorization for a proposal
 *   signer-serve                    run the signer as a separate service (MOAT_SIGNER_KEY, MOAT_OWNER_KEYS, MOAT_SIGNER_SOCKET)
 *   serve                           run the controller (MOAT_DATA, MOAT_SIGNER_SOCKET, MOAT_LISTEN, MOAT_WEB_DIR)
 *   agent-enroll / agent-sync       reference endpoint sync agent for moatd
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair, keyPairFromSeed, ownerAuthorizationString, signB64 } from "./crypto.ts";
import { Controller } from "./controller.ts";
import { Moatctl } from "./moatctl.ts";
import { Signer } from "./signer.ts";
import { serveSigner, signerClient } from "./signer-service.ts";
import { startServer } from "./server.ts";
import { enroll, syncOnce, type AgentState } from "./agent.ts";

const [cmd, ...args] = process.argv.slice(2);
const env = process.env;

function writeSecret(path: string, content: string) {
  if (existsSync(path)) throw new Error(`${path} exists; refusing to overwrite`);
  writeFileSync(path, content + "\n", { mode: 0o600 });
}

async function main() {
  switch (cmd) {
    case "owner-keygen": {
      const kp = generateKeyPair();
      writeSecret(args[0]!, kp.seedHex);
      writeFileSync(`${args[0]}.pub`, kp.publicHex + "\n");
      console.log(`owner key ${kp.keyId}: secret ${args[0]} (keep off agent-reachable machines), public ${args[0]}.pub`);
      return;
    }
    case "owner-authorize": {
      const kp = keyPairFromSeed(readFileSync(args[0]!, "utf8"));
      console.log(JSON.stringify({ key_id: kp.keyId, signature: signB64(kp.privateKey, ownerAuthorizationString(args[1]!, args[2]!)) }));
      return;
    }
    case "init": {
      const dir = args[0] ?? env.MOAT_DATA ?? "./moat-data";
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const ctl = generateKeyPair();
      writeSecret(join(dir, "controller.key"), ctl.seedHex);
      console.log(`controller key ${ctl.keyId} written to ${join(dir, "controller.key")}`);
      console.log("Next: create the signer key under the moat-signer user (moatctl keygen --out /var/lib/moat-signer/signer.key),");
      console.log("start `moat-controller signer-serve`, then `moat-controller serve` and `moat-controller token owner`.");
      return;
    }
    case "signer-serve": {
      const seed = readFileSync(env.MOAT_SIGNER_KEY ?? "/var/lib/moat-signer/signer.key", "utf8");
      const owners = (env.MOAT_OWNER_KEYS ?? "").split(",").filter(Boolean).map((f) => readFileSync(f, "utf8").trim());
      const signer = new Signer({ seedHex: seed, ownerPublicKeysHex: owners, moatctl: new Moatctl(), statePath: env.MOAT_SIGNER_STATE ?? "/var/lib/moat-signer/state.json" });
      serveSigner(signer, env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock");
      console.log(`signer ${signer.keyId} serving on ${env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock"} with ${owners.length} owner key(s)`);
      return;
    }
    case "serve":
    case "token": {
      const dir = env.MOAT_DATA ?? "./moat-data";
      const signer = await signerClient(env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock");
      const c = new Controller({ dataDir: dir, controllerSeedHex: readFileSync(join(dir, "controller.key"), "utf8"), signer, moatctl: new Moatctl(), publicUrl: env.MOAT_PUBLIC_URL ?? null, fetch: (u, i) => fetch(u, i) });
      if (cmd === "token") {
        const role = (args[0] ?? "owner") as "owner";
        console.log(c.createToken(args[1] ?? role, role).token);
        return;
      }
      const [host, port] = (env.MOAT_LISTEN ?? "127.0.0.1:7443").split(":");
      startServer(c, { host: host!, port: Number(port), webDir: env.MOAT_WEB_DIR ?? null });
      setInterval(() => void c.notifier.deliver().catch(() => {}), 5000);
      setInterval(() => c.flows.retain(new Date()), 3600_000);
      console.log(`moat controller on http://${host}:${port} (signer ${signer.keyId})`);
      return;
    }
    case "agent-enroll": {
      const [url, code, deviceId, stateFile] = args;
      const st = await enroll(url!, code!, deviceId!, process.platform === "darwin" ? "macos" : "linux", (u, i) => fetch(u, i));
      writeSecret(stateFile ?? "/var/lib/moat/agent.json", JSON.stringify(st));
      console.log(`enrolled ${deviceId}`);
      return;
    }
    case "agent-sync": {
      const stateFile = args[0] ?? "/var/lib/moat/agent.json";
      const st = JSON.parse(readFileSync(stateFile, "utf8")) as AgentState;
      for (;;) {
        try {
          const r = await syncOnce(st, env.MOAT_STATE ?? "/var/lib/moat", (u, i) => fetch(u, i), { controlSocket: env.MOAT_CONTROL_SOCKET ?? "/run/moat/control.sock" });
          writeFileSync(stateFile, JSON.stringify(st), { mode: 0o600 });
          if (r.uploaded || r.snapshot) console.log(JSON.stringify(r));
        } catch (e) {
          console.error(`sync: ${(e as Error).message}`);
        }
        await new Promise((r) => setTimeout(r, Number(env.MOAT_SYNC_SECONDS ?? 10) * 1000));
      }
    }
    default:
      console.log(readFileSync(new URL(import.meta.url), "utf8").split("*/")[0]);
  }
}

main().catch((e) => {
  console.error(`moat-controller: ${(e as Error).message}`);
  process.exit(1);
});
