/**
 * Freshness is computed by the consumer. A device's coverage label is what it last said about itself; whether that
 * statement still describes the device depends on how old it is, which the sender cannot decide for us.
 *
 * Age is measured on the controller's clock (the clock that stamped last_seen_at) plus the time this page has held
 * the snapshot, so a skewed browser clock neither freshens nor ages evidence.
 */
import type { Coverage, Device, Snapshot } from "./types";
import { COVERAGE } from "../format";

/** Matches the controller's STALE_AFTER_MS; a device silent for longer no longer supports a coverage claim. */
export const STALE_AFTER_MS = 10 * 60_000;
/** A snapshot this page has held for longer than this is itself stale (polling stopped or failing). */
export const SNAPSHOT_STALE_AFTER_MS = 2 * 60_000;

export function evidenceAgeMs(at: string | null, snap: Pick<Snapshot, "serverTime" | "fetchedAt">, now = Date.now()): number | null {
  if (!at) return null;
  const t = Date.parse(at);
  const server = Date.parse(snap.serverTime);
  const fetched = Date.parse(snap.fetchedAt);
  if (!Number.isFinite(t) || !Number.isFinite(server) || !Number.isFinite(fetched)) return null;
  return Math.max(0, server - t) + Math.max(0, now - fetched);
}

export interface Freshness {
  /** The coverage this UI will show. Never better than the device's own last claim. */
  coverage: Coverage;
  stale: boolean;
  ageMs: number | null;
  /** Why the shown coverage differs from the claim, if it does. */
  note: string | null;
}

export function deviceFreshness(d: Pick<Device, "coverage" | "lastSeen" | "platform" | "dns">, snap: Pick<Snapshot, "serverTime" | "fetchedAt">, now = Date.now()): Freshness {
  const ageMs = evidenceAgeMs(d.lastSeen, snap, now);
  if (d.dns) {
    // DNS-only: the evidence is the resolver adapter's last good poll. A failing adapter means nothing is current.
    if (d.dns.resolverHealth !== "ok") return { coverage: "unknown", stale: true, ageMs, note: `The web filter (${d.dns.resolver}) reports “${d.dns.resolverHealth.replace(/_/g, " ")}”. It last answered ${ageMs === null ? "never" : `${Math.round(ageMs / 60_000)} min ago`}, so nothing about this device is current.` };
    if (ageMs === null) return { coverage: "unknown", stale: true, ageMs, note: `Moat hasn't heard from the web filter (${d.dns.resolver}) yet.` };
  }
  if (ageMs === null) return { coverage: "unknown", stale: true, ageMs, note: "This device has never reported, so we can't say what it protects." };
  if (ageMs > STALE_AFTER_MS) {
    const min = Math.round(ageMs / 60_000);
    return { coverage: "unknown", stale: true, ageMs, note: `Last heard from ${min} min ago, when it said “${COVERAGE[d.coverage].label}”. That may still be true on the device, but it isn't current.` };
  }
  return { coverage: d.coverage, stale: false, ageMs, note: null };
}

export function snapshotAgeMs(snap: Pick<Snapshot, "fetchedAt">, now = Date.now()): number {
  return Math.max(0, now - Date.parse(snap.fetchedAt));
}
