/**
 * Reference endpoint sync agent (`moat-sync`): enrolls a device key, then periodically
 *   - uploads new spool records from moatd (`/var/lib/moat/spool/seg-*.jsonl`) with receipts,
 *   - verifies the controller's response signature (mutual authentication independent of the network),
 *   - drops a newer signed snapshot into moatd's inbox (moatd verifies the *signer* signature itself),
 *   - performs typed device actions (close a session via the local control socket).
 * It never runs shell commands and cannot alter policy: snapshots it fetches are verified by moatd against the
 * trusted signer key, not against this agent or the controller.
 */
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { connect } from "node:net";
import { generateKeyPair, keyPairFromSeed, publicFromHex, requestString, responseString, signB64, token, verifyB64, type KeyPair } from "./crypto.ts";

export interface AgentState { device_id: string; seed_hex: string; controller_url: string; controller_public_hex: string; cursor: number; last_applied: number | null }

export type AgentFetch = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export async function enroll(controllerUrl: string, code: string, deviceId: string, platform: string, f: AgentFetch, capabilities?: unknown): Promise<AgentState> {
  const kp = generateKeyPair();
  const body = JSON.stringify({ code, device_id: deviceId, name: deviceId, platform, public_hex: kp.publicHex, capabilities });
  const res = await f(`${controllerUrl.replace(/\/$/, "")}/v1/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body });
  const text = await res.text();
  if (res.status !== 200) throw new Error(`enrollment failed: HTTP ${res.status} ${text}`);
  const j = JSON.parse(text) as { controller_public_hex: string };
  return { device_id: deviceId, seed_hex: kp.seedHex, controller_url: controllerUrl, controller_public_hex: j.controller_public_hex, cursor: 0, last_applied: null };
}

export function readSpool(dir: string, after: number, limit = 2000): { seq: number }[] {
  if (!existsSync(dir)) return [];
  const out: { seq: number }[] = [];
  for (const f of readdirSync(dir).filter((x) => x.startsWith("seg-") && x.endsWith(".jsonl")).sort()) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line) as { seq: number };
        if (r.seq > after) out.push(r);
        if (out.length >= limit) return out;
      } catch {
        /* torn line */
      }
    }
  }
  return out;
}

export async function signedPost(st: AgentState, path: string, payload: unknown, f: AgentFetch, now = new Date()): Promise<{ status: number; json: Record<string, unknown> }> {
  const kp: KeyPair = keyPairFromSeed(st.seed_hex);
  const body = JSON.stringify(payload);
  const ts = now.toISOString();
  const nonce = token(18);
  const res = await f(`${st.controller_url.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-moat-device": st.device_id, "x-moat-ts": ts, "x-moat-nonce": nonce, "x-moat-sig": signB64(kp.privateKey, requestString("POST", path, ts, nonce, body)) },
    body,
  });
  const text = await res.text();
  const sig = res.headers.get("x-moat-sig"), rts = res.headers.get("x-moat-ts"), rnonce = res.headers.get("x-moat-nonce");
  if (!sig || !rts || rnonce !== nonce || !verifyB64(publicFromHex(st.controller_public_hex), responseString(res.status, rts, nonce, text), sig)) {
    throw new Error("controller response signature invalid: refusing to act on it");
  }
  return { status: res.status, json: JSON.parse(text) as Record<string, unknown> };
}

/** One sync round against moatd's state directory. */
export async function syncOnce(st: AgentState, moatState: string, f: AgentFetch, opts: { status?: unknown; capabilities?: unknown; controlSocket?: string } = {}) {
  const events = readSpool(join(moatState, "spool"), st.cursor);
  for (const e of events as { event?: { type?: string; revision?: number } }[]) {
    if (e.event?.type === "policy_applied" && typeof e.event.revision === "number") st.last_applied = Math.max(st.last_applied ?? 0, e.event.revision);
  }
  const r = await signedPost(st, "/v1/device/sync", { last_applied: st.last_applied, events, status: opts.status, capabilities: opts.capabilities }, f);
  if (r.status !== 200) throw new Error(`sync failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const acked = Number(r.json.acked_seq ?? 0);
  if (acked > st.cursor) st.cursor = acked;
  const snap = r.json.snapshot as { payload: string } | null;
  if (snap) {
    const inbox = join(moatState, "inbox");
    mkdirSync(inbox, { recursive: true });
    const name = `${Date.now()}.json`;
    writeFileSync(join(inbox, `.${name}`), JSON.stringify(snap));
    renameSync(join(inbox, `.${name}`), join(inbox, name));
  }
  for (const a of (r.json.actions as { kind: string; args: { session_id?: string } }[] | undefined) ?? []) {
    if (a.kind === "close_session" && a.args.session_id && opts.controlSocket) await closeSession(opts.controlSocket, a.args.session_id);
  }
  return { uploaded: events.length, snapshot: !!snap, actions: ((r.json.actions as unknown[]) ?? []).length };
}

function closeSession(sock: string, sessionId: string): Promise<void> {
  return new Promise((resolve) => {
    const s = connect(sock, () => s.write(JSON.stringify({ op: "close", session_id: sessionId }) + "\n"));
    s.on("data", () => s.end());
    s.on("close", () => resolve());
    s.on("error", () => resolve());
  });
}
