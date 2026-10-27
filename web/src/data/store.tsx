/**
 * App state. Two explicit modes:
 *
 *  - demo: sample data, chosen explicitly (static demo build, or "Explore sample data" on the sign-in screen).
 *    Actions are visibly simulated and never claim to have reached a device.
 *  - live: the controller's API. A failed load never shows demo data: the user sees the failure, and any data
 *    already received is kept and labeled with its age. Actions report only what the controller and endpoints
 *    actually confirmed.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { demo as demoSnapshot } from "./demo";
import type { ActionState, Device, GrantPlanView, Incident, Session, Snapshot } from "./types";
import { contractDigest, delegationProblem, loadIssuer, newIssuer, saveIssuer, signApproval, type IssuerState } from "./issuer";
import { deviceFreshness, type Freshness } from "./freshness";
import { ApiError, loadLive, makeApi, mapIncident, TOKEN_KEY, type Api, type WireGrantStatus, type WireIncident, type WireProposal } from "./api";

export type Mode = "demo" | "live";
export type Status = "signed_out" | "loading" | "ready" | "unreachable" | "unauthorized";
export const MODE_KEY = "moat.mode";
export const POLL_MS = 10_000;
export const GRANT_POLL_MS = 3_000;

export interface Store {
  mode: Mode;
  /** True only for the static demo build, where live mode does not exist. */
  demoOnly: boolean;
  status: Status;
  data: Snapshot | null;
  error: string | null;
  lastSuccessAt: string | null;
  actions: Record<string, ActionState>;
  canAct: { ok: boolean; reason: string | null };
  signIn: (token: string) => void;
  signOut: () => void;
  enterDemo: () => void;
  refresh: () => Promise<void>;
  /** Step 1: ask the controller for the exact plan; the card shows it for review. */
  allowOnce: (i: Incident) => void;
  /** Step 2: approve the reviewed plan (signed by this browser's delegated key when it has one). */
  approvePlan: (i: Incident) => void;
  cancelPlan: (i: Incident) => void;
  issuer: IssuerState | null;
  createIssuer: () => void;
  registerDelegation: (json: string) => Promise<string | null>;
  forgetIssuer: () => void;
  keepBlocked: (i: Incident) => void;
  acknowledge: (i: Incident) => void;
  rollback: (revision: number) => Promise<WireProposal | null>;
  retarget: () => Promise<void>;
  approve: (proposalId: string, authorization: { key_id: string; signature: string } | null) => Promise<void>;
  closeSession: (s: Session) => void;
  resolveRef: (ref: string) => Promise<{ incidentId: string } | { error: string }>;
  incidentById: (id: string) => Incident | undefined;
  /** Live read of a controller view (W12 detail screens). Rejects in demo mode: sample data is never fetched as live. */
  fetchLive: <T>(path: string) => Promise<T>;
  /** Owner action against a controller view (W14 review screens). Never runs in demo mode or without an owner sign-in;
   * the controller re-checks the role and every precondition. */
  postLive: <T>(path: string, body: unknown) => Promise<T>;
  /** Show a refusal or result in the toast (screens that call postLive report through it). */
  say: (msg: string) => void;
  toast: string | null;
  dismissToast: () => void;
}

const Ctx = createContext<Store | null>(null);

const step = (label: string, state: ActionState["steps"][number]["state"], detail?: string, at?: string) => ({ label, state, detail, at });

const AUTH_LABEL: Record<string, string> = { owner_key: "your owner key", narrowing: "no owner key (it only narrows access)", temporary_grant_overlay: "the limited one-time permission path", delegated_issuer: "an approval key (not your owner key)" };

/** Build the visible steps of an allow-once from the controller's grant status. Nothing is "done" without evidence. */
export function grantSteps(st: WireGrantStatus, deviceName: (id: string) => string): ActionState {
  const steps: ActionState["steps"] = [step("Requested by you", "done"), step(`Signed as rule version ${st.revision}`, "done", st.authorized_by ? `approved with ${AUTH_LABEL[st.authorized_by] ?? st.authorized_by}` : "authorizer not recorded")];
  for (const d of st.devices) {
    const name = deviceName(d.device_id);
    const delivered = ["delivered", "received", "applied", "trial", "rejected", "rolled_back"].includes(d.state);
    steps.push(step(`Delivered to ${name}`, delivered ? "done" : "active", delivered ? undefined : "waits for the device to check in"));
    if (d.state === "applied" || d.state === "trial") steps.push(step(`Applied by ${name}`, "done", `the device confirmed rule version ${d.evidence?.revision}${d.state === "trial" ? " (trial)" : ""}${d.stale ? " · it hasn't reported recently" : ""}`, d.evidence?.at));
    else if (d.state === "rejected" || d.state === "rolled_back") steps.push(step(`Rejected by ${name}`, "failed", d.evidence?.detail ?? d.state));
    else steps.push(step(`Applied by ${name}`, "pending", "not confirmed yet"));
  }
  const phase = st.state === "active" ? "active" : st.state === "pending" ? "pending" : st.state;
  return { kind: "allow_once", phase, steps, grantId: st.id, revision: st.revision ?? undefined, authorizedBy: st.authorized_by, expiresAt: st.expires_at };
}

function describe(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.offline) return `Not sent: ${e.message}. Nothing changed.`;
    if (e.status === 401) return "Your sign-in is no longer valid. Nothing changed.";
    if (e.status === 403) return `Refused: ${e.message}. Nothing changed.`;
    if (e.status === 409) return `Refused as out of date: ${e.message.replace(/^stale: /, "")}. Nothing changed; the view has been refreshed.`;
    return `Refused (${e.status}): ${e.message}. Nothing changed.`;
  }
  return `Failed: ${(e as Error).message}. Nothing changed.`;
}

export interface StoreOptions {
  /** For tests: start in this mode with this data and API. */
  initial?: { mode: Mode; data?: Snapshot; status?: Status };
  api?: Api;
  demoOnly?: boolean;
}

function initialMode(o: StoreOptions): { mode: Mode; demoOnly: boolean } {
  if (o.initial) return { mode: o.initial.mode, demoOnly: !!o.demoOnly };
  if (import.meta.env.VITE_MOAT_DEMO) return { mode: "demo", demoOnly: true };
  return { mode: typeof sessionStorage !== "undefined" && sessionStorage.getItem(MODE_KEY) === "demo" ? "demo" : "live", demoOnly: false };
}

export function StoreProvider({ children, options = {} }: { children: ReactNode; options?: StoreOptions }) {
  const [{ mode, demoOnly }, setMode] = useState(() => initialMode(options));
  const [token, setToken] = useState<string | null>(() => (typeof localStorage !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null));
  const api = useMemo<Api | null>(() => options.api ?? (token ? makeApi(token) : null), [options.api, token]);
  const [data, setData] = useState<Snapshot | null>(() => options.initial?.data ?? (initialMode(options).mode === "demo" ? { ...demoSnapshot } : null));
  const [status, setStatus] = useState<Status>(() => options.initial?.status ?? (initialMode(options).mode === "demo" ? "ready" : token || options.api ? "loading" : "signed_out"));
  const [error, setError] = useState<string | null>(null);
  const [lastSuccessAt, setLastSuccessAt] = useState<string | null>(null);
  const [actions, setActions] = useState<Record<string, ActionState>>({});
  const [extra, setExtra] = useState<Record<string, Incident>>({});
  const [toast, setToast] = useState<string | null>(null);
  const grantPolls = useRef<Map<string, number>>(new Map());
  const dataRef = useRef(data);
  dataRef.current = data;

  const refresh = useCallback(async () => {
    if (mode !== "live" || !api) return;
    try {
      const s = await loadLive(api);
      setData(s);
      setStatus("ready");
      setError(null);
      setLastSuccessAt(s.fetchedAt);
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 401) {
        setStatus("unauthorized");
        setError("The controller did not accept this sign-in.");
      } else {
        setStatus("unreachable");
        setError(err.message);
      }
    }
  }, [mode, api]);

  useEffect(() => {
    if (mode !== "live" || !api) return;
    void refresh();
    const t = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(t);
  }, [mode, api, refresh]);

  useEffect(
    () => () => {
      grantPolls.current.forEach((t) => window.clearInterval(t));
    },
    [],
  );

  const setAction = useCallback((id: string, a: ActionState | null) => setActions((m) => {
    const n = { ...m };
    if (a) n[id] = a;
    else delete n[id];
    return n;
  }), []);

  const deviceName = useCallback((id: string) => dataRef.current?.devices.find((d) => d.id === id)?.name ?? id, []);

  const canAct = useMemo(() => {
    if (mode === "demo") return { ok: true, reason: null };
    if (status !== "ready") return { ok: false, reason: status === "unreachable" ? "Moat can't reach your controller, so actions are paused until this view is up to date." : "Sign in to act." };
    if (data?.viewer?.role !== "owner") return { ok: false, reason: `Signed in as ${data?.viewer?.role ?? "unknown role"}: read only. Owner actions need an owner sign-in.` };
    return { ok: true, reason: null };
  }, [mode, status, data]);

  const watchGrant = useCallback(
    (incidentId: string, grantId: string) => {
      if (!api || grantPolls.current.has(incidentId)) return;
      const tick = async () => {
        try {
          const st = await api.get<WireGrantStatus>(`/v1/grants/${encodeURIComponent(grantId)}`);
          setAction(incidentId, grantSteps(st, deviceName));
          if (st.state !== "pending") {
            window.clearInterval(grantPolls.current.get(incidentId));
            grantPolls.current.delete(incidentId);
            if (st.state === "active") setToast(`Allowed: the device confirmed rule version ${st.revision}. It ends on its own at the original time.`);
            if (st.state === "rejected") setToast("The device refused this change. Nothing was allowed.");
          }
        } catch (e) {
          setActions((m) => (m[incidentId] ? { ...m, [incidentId]: { ...m[incidentId]!, error: `Status unknown: ${(e as Error).message}` } } : m));
        }
      };
      void tick();
      grantPolls.current.set(incidentId, window.setInterval(() => void tick(), GRANT_POLL_MS));
    },
    [api, deviceName, setAction],
  );

  const [issuer, setIssuer] = useState<IssuerState | null>(() => loadIssuer());
  const opIds = useRef<Map<string, string>>(new Map());

  const allowOnce = useCallback(
    (i: Incident) => {
      if (mode === "demo") {
        setAction(i.id, { kind: "allow_once", phase: "simulated", steps: [step("Demo only: nothing was sent", "done", "With a real controller, Moat first shows you the exact permission (device, task, address and time limit), you approve it, and the card waits for the device to confirm.")] });
        setToast("Demo: nothing was sent to a device.");
        return;
      }
      if (!api || !canAct.ok) return;
      const policy = dataRef.current?.policyRevision;
      // the approver is fixed in the plan: this browser's delegated key when it covers the device, else the owner path
      const approver = issuer?.delegation && !delegationProblem(issuer, issuer.delegation) && issuer.delegation.scope.devices.includes(i.deviceId) ? issuer.keyId : null;
      // one operation id per click (and approver): a retried request returns the same plan and the same deadline
      const opKey = `${i.id}|${approver ?? "owner"}`;
      const op = opIds.current.get(opKey) ?? `ui-${i.id.slice(-12)}-${Math.random().toString(36).slice(2, 12)}`.replace(/[^A-Za-z0-9:._-]/g, "x");
      opIds.current.set(opKey, op);
      setAction(i.id, { kind: "allow_once", phase: "planning", steps: [step("Preparing the exact permission", "active", "waiting for the controller")] });
      api
        .post<GrantPlanView>("/v1/actions/allow-once/plan", { incident_id: i.id, incident_revision: i.revision, policy_revision: policy, operation_id: op, ...(approver ? { issuer_key_id: approver } : {}) })
        .then((p) => setAction(i.id, { kind: "allow_once", phase: "review", plan: p, steps: [step("Review the exact permission", "active", "nothing is allowed until you approve it")] }))
        .catch((e) => {
          opIds.current.delete(opKey);
          setAction(i.id, { kind: "allow_once", phase: e instanceof ApiError && !e.offline ? "rejected" : "failed", error: describe(e), steps: [step("Prepare", "failed", describe(e))] });
          if (e instanceof ApiError && e.status === 409) void refresh();
        });
    },
    [mode, api, canAct.ok, setAction, refresh, issuer],
  );

  const clearOps = (incidentId: string) => {
    for (const k of [...opIds.current.keys()]) if (k.startsWith(`${incidentId}|`)) opIds.current.delete(k);
  };

  const approvePlan = useCallback(
    (i: Incident) => {
      const cur = actions[i.id];
      if (!api || !canAct.ok || !cur?.plan) return;
      const plan = cur.plan;
      const usable = !!issuer?.delegation && !delegationProblem(issuer, issuer.delegation) && issuer.delegation.scope.devices.includes(plan.plan.scope.device_id) && plan.plan.issuer.key_id === issuer.keyId;
      // sign only what is on screen: the digest is recomputed here from the rendered plan, never taken on trust
      if (usable && contractDigest(plan.plan) !== plan.digest) {
        setAction(i.id, { kind: "allow_once", phase: "rejected", plan, error: "Refused: what the controller would sign doesn't match what you saw. Nothing was signed.", steps: [step("Approve", "failed", "the permission didn't match")] });
        return;
      }
      const body: Record<string, unknown> = { plan_id: plan.plan_id };
      if (usable) Object.assign(body, { issuer_key_id: issuer!.keyId, issuer_signature: signApproval(issuer!, plan.digest) });
      setAction(i.id, { ...cur, phase: "sending", steps: [step(usable ? "Approved and signed on this device" : "Approved", "done", usable ? `approval key ${issuer!.keyId}` : "this browser has no approval key: the controller decides whether your sign-in may approve"), step("Signing", "active", "waiting for the controller and signer")] });
      api
        .post<{ grant_id: string; revision: number; authorized_by: string; expires_at: string }>("/v1/actions/allow-once", body)
        .then((r) => {
          clearOps(i.id);
          setAction(i.id, { kind: "allow_once", phase: "pending", plan, grantId: r.grant_id, revision: r.revision, authorizedBy: r.authorized_by, expiresAt: r.expires_at, steps: [step("Requested by you", "done"), step(`Signed as rule version ${r.revision}`, "done", `approved with ${AUTH_LABEL[r.authorized_by] ?? r.authorized_by}`), step("Delivered and applied", "active", "waiting for the device to confirm")] });
          watchGrant(i.id, r.grant_id);
        })
        .catch((e) => {
          const needIssuer = e instanceof ApiError && /delegated issuer/.test(e.message);
          setAction(i.id, { kind: "allow_once", phase: e instanceof ApiError && !e.offline ? "rejected" : "failed", plan, error: needIssuer ? "Refused: this controller only accepts approvals from a phone or browser with its own approval key. Set one up under Devices → Approve from this browser. Nothing changed." : describe(e), steps: [step("Approve", "failed", needIssuer ? "needs an approval key" : describe(e))] });
          if (e instanceof ApiError && e.status === 409) {
            clearOps(i.id);
            void refresh();
          }
        });
    },
    [actions, api, canAct.ok, issuer, setAction, watchGrant, refresh],
  );

  const cancelPlan = useCallback((i: Incident) => setAction(i.id, null), [setAction]);

  const createIssuer = useCallback(() => {
    const st = newIssuer();
    saveIssuer(st);
    setIssuer(st);
  }, []);
  const forgetIssuer = useCallback(() => {
    saveIssuer(null);
    setIssuer(null);
  }, []);
  const registerDelegation = useCallback(
    async (json: string): Promise<string | null> => {
      if (!issuer) return "Create this device's approval key first.";
      let d: unknown;
      try {
        d = JSON.parse(json);
      } catch {
        return "That isn't the text the command printed. Paste all of it.";
      }
      const bad = delegationProblem(issuer, d);
      if (bad) return bad;
      if (mode === "live") {
        if (!api) return "Sign in first.";
        try {
          await api.post("/v1/issuers", { delegation: d });
        } catch (e) {
          return describe(e).replace(/ Nothing changed\.$/, "");
        }
      }
      const st = { ...issuer, delegation: d as IssuerState["delegation"] };
      saveIssuer(st);
      setIssuer(st);
      return null;
    },
    [issuer, mode, api],
  );

  const incidentMutation = useCallback(
    (i: Incident, kind: "keep_blocked" | "acknowledge") => {
      if (mode === "demo") {
        setData((d) => (d ? { ...d, incidents: d.incidents.map((x) => (x.id === i.id ? { ...x, state: kind === "keep_blocked" ? "resolved" : "acknowledged" } : x)) } : d));
        setAction(i.id, { kind, phase: "simulated", steps: [step(kind === "keep_blocked" ? "Kept blocked (demo)" : "Acknowledged (demo)", "done", "no rule changed")] });
        setToast(kind === "keep_blocked" ? "Demo: kept blocking. Nothing was sent." : "Demo: acknowledged. Nothing was sent.");
        return;
      }
      if (!api || !canAct.ok) return;
      setAction(i.id, { kind, phase: "sending", steps: [step(kind === "keep_blocked" ? "Keep blocked" : "Acknowledge", "active", "waiting for the controller")] });
      api
        .post<WireIncident>(`/v1/incidents/${encodeURIComponent(i.id)}/${kind === "keep_blocked" ? "resolve" : "acknowledge"}`, { expected_revision: i.revision })
        .then((w) => {
          const m = mapIncident(w);
          setData((d) => (d ? { ...d, incidents: d.incidents.map((x) => (x.id === i.id ? m : x)) } : d));
          setExtra((x) => (x[i.id] ? { ...x, [i.id]: m } : x));
          setAction(i.id, { kind, phase: "done", steps: [step(kind === "keep_blocked" ? "Kept blocked" : "Acknowledged", "done", kind === "keep_blocked" ? "Saved. No rule changed." : "Seen. Acknowledging never allows anything.")] });
          setToast(kind === "keep_blocked" ? "Kept blocking. No rule changed." : "Acknowledged. Nothing was allowed.");
        })
        .catch((e) => {
          setAction(i.id, { kind, phase: e instanceof ApiError && !e.offline ? "rejected" : "failed", error: describe(e), steps: [step(kind === "keep_blocked" ? "Keep blocked" : "Acknowledge", "failed", describe(e))] });
          if (e instanceof ApiError && e.status === 409) void refresh();
        });
    },
    [mode, api, canAct.ok, setAction, refresh],
  );

  const retarget = useCallback(async () => {
    if (mode === "demo") {
      setToast("Demo: this would resend your current rules to every device; nothing was sent.");
      return;
    }
    if (!api || !canAct.ok) return;
    try {
      const r = await api.post<{ retargeted: boolean; revision?: number; missing: string[] }>("/v1/policy/retarget", {});
      setToast(r.retargeted ? `Rule version ${r.revision} prepared for ${r.missing.join(", ")} too; they get it when they next check in.` : "Every device already has your current rules.");
      void refresh();
    } catch (e) {
      setToast(describe(e));
    }
  }, [mode, api, canAct.ok, refresh]);

  const rollback = useCallback(
    async (revision: number): Promise<WireProposal | null> => {
      if (mode === "demo") {
        setToast(`Demo: going back would prepare a change that restores version ${revision}'s rules; nothing was sent.`);
        return null;
      }
      if (!api || !canAct.ok) return null;
      try {
        return await api.post<WireProposal>("/v1/policy/rollback", { to_revision: revision, message: `Roll back to revision ${revision}` });
      } catch (e) {
        setToast(describe(e));
        return null;
      }
    },
    [mode, api, canAct.ok],
  );

  const approve = useCallback(
    async (proposalId: string, authorization: { key_id: string; signature: string } | null) => {
      if (mode !== "live" || !api || !canAct.ok) return;
      try {
        const r = await api.post<{ revision: number; authorized_by: string }>(`/v1/policy/proposals/${encodeURIComponent(proposalId)}/approve`, { owner_authorization: authorization });
        setToast(`Signed as rule version ${r.revision} (approved with ${AUTH_LABEL[r.authorized_by] ?? r.authorized_by}). Devices apply it when they next check in, and each one confirms.`);
        void refresh();
      } catch (e) {
        setToast(describe(e));
        throw e;
      }
    },
    [mode, api, canAct.ok, refresh],
  );

  const closeSession = useCallback(
    (s: Session) => {
      if (mode === "demo") {
        setToast("Demo: nothing was sent.");
        return;
      }
      if (!api || !canAct.ok) return;
      api
        .post<{ state: string }>(`/v1/harness/devices/${encodeURIComponent(s.deviceId)}/sessions/${encodeURIComponent(s.id)}/close`, {})
        .then(() => {
          setToast("Asked the device to end this task. It ends when the device confirms.");
          void refresh();
        })
        .catch((e) => setToast(describe(e)));
    },
    [mode, api, canAct.ok, refresh],
  );

  const resolveRef = useCallback(
    async (ref: string): Promise<{ incidentId: string } | { error: string }> => {
      if (mode === "demo") {
        const { demoRefs } = await import("./demo");
        const id = demoRefs[ref];
        return id ? { incidentId: id } : { error: "This notification link is unknown or has expired. Nothing else was opened." };
      }
      if (!api) return { error: "Sign in to open this notification." };
      try {
        const w = await api.get<WireIncident>(`/v1/r/${encodeURIComponent(ref)}`);
        const m = mapIncident(w);
        setExtra((x) => ({ ...x, [m.id]: m }));
        return { incidentId: m.id };
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) return { error: "This notification link is unknown, or what it pointed to no longer exists. Nothing else was opened." };
        return { error: describe(e).replace(/ Nothing changed\.$/, "") };
      }
    },
    [mode, api],
  );

  const incidentById = useCallback((id: string) => data?.incidents.find((x) => x.id === id) ?? extra[id], [data, extra]);

  const signIn = useCallback((t: string) => {
    localStorage.setItem(TOKEN_KEY, t);
    sessionStorage.removeItem(MODE_KEY);
    setMode({ mode: "live", demoOnly: false });
    setData(null);
    setStatus("loading");
    setToken(t);
  }, []);
  const signOut = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(MODE_KEY);
    grantPolls.current.forEach((t) => window.clearInterval(t));
    grantPolls.current.clear();
    setToken(null);
    setMode({ mode: "live", demoOnly: false });
    setData(null);
    setActions({});
    setStatus("signed_out");
  }, []);
  const enterDemo = useCallback(() => {
    sessionStorage.setItem(MODE_KEY, "demo");
    setMode({ mode: "demo", demoOnly: false });
    setData({ ...demoSnapshot });
    setActions({});
    setStatus("ready");
  }, []);

  const value: Store = {
    mode,
    demoOnly,
    status,
    data,
    error,
    lastSuccessAt,
    actions,
    canAct,
    signIn,
    signOut,
    enterDemo,
    refresh,
    allowOnce,
    approvePlan,
    cancelPlan,
    issuer,
    createIssuer,
    registerDelegation,
    forgetIssuer,
    keepBlocked: (i) => incidentMutation(i, "keep_blocked"),
    acknowledge: (i) => incidentMutation(i, "acknowledge"),
    rollback,
    retarget,
    approve,
    closeSession,
    resolveRef,
    incidentById,
    postLive: <T,>(path: string, body: unknown) => {
      if (mode !== "live" || !api) return Promise.reject(new Error("Demo: nothing was sent."));
      if (!canAct.ok) return Promise.reject(new Error(canAct.reason ?? "Owner sign-in required."));
      return api.post<T>(path, body).catch((e) => Promise.reject(new Error(describe(e))));
    },
    say: (msg: string) => setToast(msg),
    fetchLive: <T,>(path: string) => (mode === "live" && api ? api.get<T>(path) : Promise.reject(new Error("Sign in to a controller: sample data has no live view."))),
    toast,
    dismissToast: () => setToast(null),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useStore(): Store {
  const s = useContext(Ctx);
  if (!s) throw new Error("StoreProvider missing");
  return s;
}

/** Screens render only with data; the App shell handles signed-out, loading and failure states. */
/** Coverage as this page computes it from evidence age, never the device's own label alone. */
export function useFreshness(): (d: Device) => Freshness {
  const data = useData();
  return (d: Device) => deviceFreshness(d, data);
}

export function useData(): Snapshot {
  const s = useStore();
  if (!s.data) throw new Error("useData outside a loaded state");
  return s.data;
}
