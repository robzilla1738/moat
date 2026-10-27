import type { IconName } from "./components/ui";
import type { Coverage, Support } from "./data/types";

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

export const COVERAGE: Record<Coverage, { label: string; tone: string; icon: IconName; claim: string }> = {
  "protected-session": { label: "Protected session", tone: "green", icon: "lock", claim: "Selected workloads run inside a tested OS boundary established before launch." },
  enforced: { label: "Enforced", tone: "blue", icon: "shield", claim: "Policy decides supported flows on this device." },
  monitoring: { label: "Monitoring", tone: "neutral", icon: "eye", claim: "Traffic is observed and recorded. It is permitted, not enforced." },
  "dns-only": { label: "DNS only", tone: "violet", icon: "globe", claim: "Resolver queries only. No app, process, connection or byte count." },
  degraded: { label: "Degraded", tone: "amber", icon: "alert", claim: "Something the policy needs is not in force. See why." },
  "recovery-required": { label: "Recovery required", tone: "red", icon: "wrench", claim: "The device could not reconcile its activation state. It keeps its last verified policy and needs you at the device; nothing is reset or guessed." },
  "rollback-pending": { label: "Rollback pending", tone: "red", icon: "undo", claim: "A trial rollback could not reinstall the previous policy, so the trial revision is still in force. Recover at the device." },
  isolated: { label: "Isolated", tone: "red", icon: "lock", claim: "Emergency isolation: only the recovery paths you chose are open." },
  unknown: { label: "Unknown", tone: "neutral", icon: "help", claim: "No current report from this device. Moat cannot say what it enforces right now." },
};

export const SUPPORT: Record<Support, { label: string; tone: string; icon: IconName }> = {
  supported: { label: "Supported", tone: "green", icon: "check" },
  partial: { label: "Partial", tone: "amber", icon: "alert" },
  untested: { label: "Needs device proof", tone: "blue", icon: "clock" },
  unsupported: { label: "Not available", tone: "neutral", icon: "minus" },
};
