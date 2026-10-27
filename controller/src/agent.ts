/**
 * Reference endpoint sync agent (`moat-sync`): enrolls a device key, then periodically
 *   - uploads new spool records from moatd (`/var/lib/moat/spool/seg-*.jsonl`) with receipts,
 *   - verifies the controller's response signature (mutual authentication independent of the network),
 *   - drops a newer signed snapshot into moatd's inbox (moatd verifies the *signer* signature itself),
 *   - performs typed device actions (close a session via the local control socket),
 *   - reads moatd's `spool/sync-state.json` (`moat.spool_sync_state.v1`: spool_low_seq, acked_seq, next_seq,
 *     local_change) into the sync body and writes the controller's contiguous `acked_seq` to `spool/acked`
 *     (docs/fleet-sync.md). It never lowers that file and never writes a value beyond the last sequence moatd wrote.
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

export const SYNC_STATE_SCHEMA = "moat.spool_sync_state.v1";
export interface LocalChangeReport { revision: number; digest: string; broadening: boolean; authorized_by: string }
export interface SpoolSyncState { schema: string; device_id: string; boot_id: string; spool_low_seq: number; acked_seq: number; next_seq: number; local_change: LocalChangeReport | null }

const isSeq = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;

/**
 * Read moatd's sync state. A missing, torn or unknown-schema file yields null: the agent then sends no
 * spool_low_seq/local_change (holes stay pending) rather than inventing one.
 */
export function readSyncState(spoolDir: string): SpoolSyncState | null {
  let j: Record<string, unknown>;
  try {
    j = JSON.parse(readFileSync(join(spoolDir, "sync-state.json"), "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (j.schema !== SYNC_STATE_SCHEMA || typeof j.device_id !== "string" || !isSeq(j.spool_low_seq) || !isSeq(j.acked_seq) || !isSeq(j.next_seq)) return null;
  if (j.spool_low_seq > j.next_seq || j.acked_seq >= Math.max(j.next_seq, 1)) return null;
  let lc: LocalChangeReport | null = null;
  const l = j.local_change as Record<string, unknown> | null | undefined;
  if (l != null) {
    if (!isSeq(l.revision) || typeof l.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(l.digest) || typeof l.broadening !== "boolean") return null;
    lc = { revision: l.revision, digest: l.digest, broadening: l.broadening, authorized_by: String(l.authorized_by ?? "") };
  }
  return { schema: SYNC_STATE_SCHEMA, device_id: j.device_id, boot_id: String(j.boot_id ?? ""), spool_low_seq: j.spool_low_seq, acked_seq: j.acked_seq, next_seq: j.next_seq, local_change: lc };
}

/** The value currently in `spool/acked`, or 0. */
export function readAckFile(spoolDir: string): number {
  try {
    const n = Number(readFileSync(join(spoolDir, "acked"), "utf8").trim());
    return isSeq(n) ? n : 0;
  } catch {
    return 0;
  }
}

/**
 * Write the controller's contiguous acked_seq to `spool/acked` atomically. Never lowers it (acknowledgement does not
 * move backwards) and never writes past the last sequence moatd reports having written (`next_seq - 1`): a
 * controller claiming more than the endpoint produced is not believed. Returns what was written, or why not.
 */
export function writeAck(spoolDir: string, acked: number, state: SpoolSyncState | null): { written: number | null; reason?: string } {
  if (!isSeq(acked)) return { written: null, reason: "acked_seq is not a sequence number" };
  if (state && acked > state.next_seq - 1) return { written: null, reason: `acked_seq ${acked} is beyond the last sequence written (${state.next_seq - 1})` };
  const cur = Math.max(readAckFile(spoolDir), state?.acked_seq ?? 0);
  if (acked <= cur) return { written: null, reason: acked < cur ? `acked_seq ${acked} is lower than ${cur}; acknowledgement never moves backwards` : "unchanged" };
  if (!existsSync(spoolDir)) return { written: null, reason: "no spool directory" };
  const tmp = join(spoolDir, `.acked.${process.pid}`);
  writeFileSync(tmp, String(acked));
  renameSync(tmp, join(spoolDir, "acked"));
  return { written: acked };
}

/** One sync round against moatd's state directory. */
export async function syncOnce(st: AgentState, moatState: string, f: AgentFetch, opts: { status?: unknown; capabilities?: unknown; controlSocket?: string } = {}) {
  const spoolDir = join(moatState, "spool");
  const state = readSyncState(spoolDir);
  if (state && state.device_id !== st.device_id) throw new Error(`spool belongs to device ${state.device_id}, not ${st.device_id}: refusing to upload it`);
  // Records at or below moatd's accepted ack were already stored by the controller.
  const after = Math.max(st.cursor, state?.acked_seq ?? 0);
  const events = readSpool(spoolDir, after);
  for (const e of events as { event?: { type?: string; revision?: number } }[]) {
    if (e.event?.type === "policy_applied" && typeof e.event.revision === "number") st.last_applied = Math.max(st.last_applied ?? 0, e.event.revision);
  }
  const body: Record<string, unknown> = { last_applied: st.last_applied, events, status: opts.status, capabilities: opts.capabilities };
  if (state) {
    body.spool_low_seq = state.spool_low_seq;
    body.local_change = state.local_change;
  }
  // A transport failure (controller outage) throws here: nothing is acknowledged and the spool keeps everything.
  const r = await signedPost(st, "/v1/device/sync", body, f);
  if (r.status !== 200) throw new Error(`sync failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const acked = Number(r.json.acked_seq ?? 0);
  const ack = writeAck(spoolDir, acked, state);
  // The cursor follows the controller: a lower acked_seq (e.g. a restored controller) means resend what is still held.
  if (isSeq(acked) && (!state || acked <= state.next_seq - 1)) st.cursor = acked;
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
  return {
    uploaded: events.length,
    snapshot: !!snap,
    actions: ((r.json.actions as unknown[]) ?? []).length,
    acked_seq: acked,
    ack_written: ack.written,
    ...(ack.reason && ack.reason !== "unchanged" ? { ack_refused: ack.reason } : {}),
    pending_ranges: (r.json.pending_ranges as [number, number][] | undefined) ?? [],
    held: (r.json.held as string | null | undefined) ?? null,
  };
}

function closeSession(sock: string, sessionId: string): Promise<void> {
  return new Promise((resolve) => {
    const s = connect(sock, () => s.write(JSON.stringify({ op: "close", session_id: sessionId }) + "\n"));
    s.on("data", () => s.end());
    s.on("close", () => resolve());
    s.on("error", () => resolve());
  });
}
