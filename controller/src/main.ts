#!/usr/bin/env node
/**
 * moat-controller CLI.
 *
 *   init <dir>                      create controller key, owner token, and print next steps
 *   owner-keygen <file>             generate an owner key (keep it on the owner's device, never in agent workspaces)
 *   owner-authorize <file> <subject> <digest>   sign a broadening authorization for a proposal
 *   delegate-issuer <owner-file> <issuer-public-hex> --devices a,b [--max-ttl 3600] [--days 30] [--kinds allow_once] [--label phone]
 *                                   delegate a bounded approval scope (e.g. phone allow-once) to another key
 *   signer-serve                    run the signer as a separate service (MOAT_SIGNER_KEY, MOAT_OWNER_KEYS, MOAT_SIGNER_SOCKET)
 *   serve                           run the controller (MOAT_DATA, MOAT_SIGNER_SOCKET, MOAT_LISTEN, MOAT_WEB_DIR;
 *                                   optional MOAT_RESOLVERS_FILE, MOAT_DK_URL + MOAT_DK_SOURCE_KEY_FILE: docs/integrations.md)
 *   agent-enroll / agent-sync       reference endpoint sync agent for moatd
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { delegationString, generateKeyPair, keyIdOf, keyPairFromSeed, ownerAuthorizationString, signB64 } from "./crypto.ts";
import { Controller } from "./controller.ts";
import { Moatctl } from "./moatctl.ts";
import { Signer } from "./signer.ts";
import { serveSigner, signerClient } from "./signer-service.ts";
import { startServer } from "./server.ts";
import { enroll, syncOnce, type AgentState } from "./agent.ts";
import { parseResolverConfig } from "./integrations.ts";

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
    case "delegate-issuer": {
      const kp = keyPairFromSeed(readFileSync(args[0]!, "utf8"));
      const pub = String(args[1] ?? "");
      const opt = (name: string, dflt: string) => {
        const i = args.indexOf(`--${name}`);
        return i > 0 ? String(args[i + 1]) : dflt;
      };
      const devices = opt("devices", "").split(",").filter(Boolean);
      if (!devices.length) throw new Error("--devices is required: a delegation names the exact devices it covers");
      const body = { schema: "moat.delegation.v1", issuer_key_id: keyIdOf(pub), issuer_public_hex: pub, label: opt("label", "phone"), scope: { kinds: opt("kinds", "allow_once").split(","), devices, max_ttl_seconds: Math.min(86400, Number(opt("max-ttl", "3600"))) }, not_after: new Date(Date.now() + Number(opt("days", "30")) * 86400_000).toISOString(), owner_key_id: kp.keyId };
      console.log(JSON.stringify({ ...body, signature: signB64(kp.privateKey, delegationString(body)) }));
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
      const signer = new Signer({ seedHex: seed, ownerPublicKeysHex: owners, moatctl: new Moatctl(), statePath: env.MOAT_SIGNER_STATE ?? "/var/lib/moat-signer/state.json", controllerAttestedGrants: env.MOAT_SIGNER_CONTROLLER_GRANTS === "1" });
      serveSigner(signer, env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock");
      console.log(`signer ${signer.keyId} serving on ${env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock"} with ${owners.length} owner key(s); temporary grants need ${signer.controllerAttestedGrants ? "a delegated issuer or an authenticated owner session (MOAT_SIGNER_CONTROLLER_GRANTS=1)" : "a delegated issuer's signature"}`);
      return;
    }
    case "serve":
    case "token": {
      const dir = env.MOAT_DATA ?? "./moat-data";
      const signer = await signerClient(env.MOAT_SIGNER_SOCKET ?? "/run/moat-signer/signer.sock");
      const c = new Controller({ dataDir: dir, controllerSeedHex: readFileSync(join(dir, "controller.key"), "utf8"), signer, moatctl: new Moatctl(), publicUrl: env.MOAT_PUBLIC_URL ?? null, fetch: (u, i) => fetch(u, i) });
      for (const r of await c.recoverPublications()) console.log(`publication ${r.id}: ${r.outcome}`);
      if (cmd === "token") {
        const role = (args[0] ?? "owner") as "owner";
        console.log(c.createToken(args[1] ?? role, role).token);
        return;
      }
      const [host, port] = (env.MOAT_LISTEN ?? "127.0.0.1:7443").split(":");
      startServer(c, { host: host!, port: Number(port), webDir: env.MOAT_WEB_DIR ?? null });
      setInterval(() => void c.notifier.deliver().catch(() => {}), 5000);
      setInterval(() => c.flows.retain(new Date()), 3600_000);
      if (env.MOAT_RESOLVERS_FILE) {
        c.integrations.configureResolvers(parseResolverConfig(readFileSync(env.MOAT_RESOLVERS_FILE, "utf8")), (u, i) => fetch(u, i));
        setInterval(() => void c.integrations.pollDue().catch((e) => console.error(`dns: ${(e as Error).message}`)), 5000);
      }
      if (env.MOAT_DK_URL && env.MOAT_DK_SOURCE_KEY_FILE) {
        c.integrations.configureDk(env.MOAT_DK_URL, readFileSync(env.MOAT_DK_SOURCE_KEY_FILE, "utf8").trim(), (u, i) => fetch(u, i));
        setInterval(() => {
          const dk = c.integrations.dk!;
          if (dk.due()) void dk.push().catch((e) => console.error(`digital kingdom: ${(e as Error).message}`));
        }, 10_000);
      }
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
