/** Shared W12+ controller test helpers: enroll a device in-process and build endpoint flow events. */
import { generateKeyPair } from "../src/crypto.ts";
import type { Fixture } from "./helpers.ts";

export const CURL_RULE = `
[[rules]]
id = "curl-allow-example"
description = "curl may reach example.org (skipped with report where per-app hostname rules cannot be enforced)."
action = "allow"
on_unsupported = "skip_with_report"
selector = { apps = [{ executable = "/usr/bin/curl" }] }
destinations = { hosts = ["example.org"] }
provenance = { kind = "git", reference = "test" }
`;

export function enroll(f: Fixture, id = "mbp", platform = "macos") {
  const owner = f.c.authenticate(f.ownerToken)!;
  const { code } = f.c.createEnrollmentCode(owner);
  f.c.enroll({ code, device_id: id, platform, public_hex: generateKeyPair().publicHex, capabilities: { capabilities: { session_enforcement: { support: "supported" }, app_enforcement: { support: "unsupported", note: "nftables" } } } });
  return f.c.db.prepare("SELECT * FROM devices WHERE id = ?").get(id) as never;
}

let seq = 0;
/** Advance the endpoint sequence (simulates lost events); returns the new value. */
export function nextSeq(by = 1) {
  seq += by;
  return seq;
}
export function flow(f: Fixture, o: { exe?: string | null; family?: string; signer?: string; ip?: string; host?: string; port?: number; verdict?: "allow" | "deny"; observed?: boolean; rule?: string; revision?: number; minutesAgo?: number; device?: string }) {
  const at = new Date(f.clock.t - (o.minutesAgo ?? 0) * 60_000).toISOString();
  const app = o.exe === null ? { family: o.family ?? "curl" } : { family: o.family ?? "curl", executable: o.exe ?? "/usr/bin/curl", ...(o.signer ? { team_id: o.signer } : {}) };
  return {
    seq: ++seq,
    at,
    event: {
      type: "flow",
      attempt: { id: `f${seq}`, device_id: o.device ?? "mbp", app, remote_ip: o.ip ?? "93.184.215.14", remote_port: o.port ?? 443, transport: "tcp", at, ...(o.host ? { hostname: { name: o.host, source: "sni", confidence: "medium" } } : {}) },
      decision: { verdict: o.verdict ?? "allow", permitted_by_observation: o.observed ?? false, rule: o.rule, profile: "ordinary-desktop-learning", policy_revision: o.revision ?? 1 },
    },
  };
}

