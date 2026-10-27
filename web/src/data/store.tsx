import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { demo } from "./demo";
import type { ActionState, Incident, Snapshot } from "./types";
import { loadLive } from "./api";

interface Store {
  data: Snapshot;
  live: boolean;
  allowOnce: (incidentId: string) => void;
  keepBlocked: (incidentId: string) => void;
  acknowledge: (incidentId: string) => void;
  rollback: (revision: number) => void;
  toast: string | null;
  dismissToast: () => void;
}

const Ctx = createContext<Store | null>(null);

const step = (label: string, state: ActionState["steps"][number]["state"], detail?: string) => ({ label, state, detail, at: state === "done" ? new Date().toISOString() : undefined });

export function StoreProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<Snapshot>(demo);
  const [live, setLive] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    if (import.meta.env.VITE_MOAT_DEMO) return;
    let cancelled = false;
    loadLive().then((s) => {
      if (s && !cancelled) {
        setData(s);
        setLive(true);
      }
    });
    return () => {
      cancelled = true;
      timers.current.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  const patchIncident = useCallback((id: string, f: (i: Incident) => Incident) => {
    setData((d) => ({ ...d, incidents: d.incidents.map((i) => (i.id === id ? f(i) : i)) }));
  }, []);

  const allowOnce = useCallback(
    (id: string) => {
      const expiresAt = new Date(Date.now() + 3600_000).toISOString();
      // Each step is shown separately: an owner request is not a signed revision, and delivery is not application.
      patchIncident(id, (i) => ({
        ...i,
        action: { kind: "allow_once", expiresAt, steps: [step("Requested by you", "done"), step("Signed as revision 15", "active", "bounded grant: this session, this destination, 1 h"), step("Delivered to Omarchy", "pending"), step("Applied by endpoint", "pending")] },
      }));
      const advance = (n: number, delay: number) =>
        timers.current.push(
          window.setTimeout(() => {
            patchIncident(id, (i) => (i.action ? { ...i, action: { ...i.action, steps: i.action.steps.map((s, k) => (k < n ? { ...s, state: "done", at: s.at ?? new Date().toISOString() } : k === n ? { ...s, state: "active" } : s)) } } : i));
            if (n === 4) {
              setData((d) => ({ ...d, policyRevision: 15, grants: [{ id: "g-42", destination: "oss-cn-beijing.aliyuncs.com:443", scope: "session 20261026-7c1e9a", expiresAt, by: "robert" }, ...d.grants] }));
              setToast("Applied on Omarchy. Allowed for this session for 1 hour.");
            }
          }, delay),
        );
      advance(2, 700);
      advance(3, 1500);
      advance(4, 2300);
    },
    [patchIncident],
  );

  const keepBlocked = useCallback(
    (id: string) => {
      patchIncident(id, (i) => ({ ...i, state: "resolved", action: { kind: "keep_blocked", steps: [step("Kept blocked", "done", "no policy change")] } }));
      setToast("Kept blocked. Nothing changed on your devices.");
    },
    [patchIncident],
  );

  const acknowledge = useCallback((id: string) => patchIncident(id, (i) => ({ ...i, state: "acknowledged" })), [patchIncident]);

  const rollback = useCallback((rev: number) => {
    setToast(`Prepared revision ${demo.policyRevision + 1} with revision ${rev}'s rules. It broadens access, so it needs your owner key to sign.`);
  }, []);

  const value = useMemo(() => ({ data, live, allowOnce, keepBlocked, acknowledge, rollback, toast, dismissToast: () => setToast(null) }), [data, live, allowOnce, keepBlocked, acknowledge, rollback, toast]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useStore() {
  const s = useContext(Ctx);
  if (!s) throw new Error("StoreProvider missing");
  return s;
}
