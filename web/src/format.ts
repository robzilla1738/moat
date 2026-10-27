import type { IconName, Tone } from "./components/ui";
import type { Coverage, Support } from "./data/types";
import vocabulary from "../../brand/vocabulary.json";

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

/** "checked just now", "checked 5m ago", "never checked": the glossary's word for evidence age. */
export function checked(iso: string | null | undefined, now = Date.now()): string {
  return iso ? `checked ${ago(iso, now)}` : "never checked";
}

export function until(iso: string, now = Date.now()): string {
  const m = Math.round((Date.parse(iso) - now) / 60000);
  if (m <= 0) return "expired";
  if (m < 60) return `${m} min left`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m left`;
}

export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 10_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return `${Math.round(n / 1000)}k`;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

type Entry = { label: string; tone: Tone; icon: IconName };
/** The shared status vocabulary (brand/vocabulary.json): the same words on web and macOS. */
export const COVERAGE = vocabulary.coverage as Record<Coverage, Entry & { sf: string; meaning: string }>;
export const SUPPORT = vocabulary.support as Record<Support, Entry>;
export const VERDICT = vocabulary.verdict as Record<"blocked" | "allowed" | "observed" | "isolated", { label: string; tone: Tone }>;

/** Coverage levels that mean "protected" for the purpose of the headline count. */
export const PROTECTED: Coverage[] = ["enforced", "protected-session"];
/** Coverage levels that are a problem the owner should see (never hidden). */
export const NEEDS_ATTENTION: Coverage[] = ["degraded", "unknown", "recovery-required", "rollback-pending", "isolated"];
