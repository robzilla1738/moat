import { useState } from "react";
import { Badge, Card, Chain, Empty, Icon, Ident, SectionTitle, Steps } from "../components/ui";
import { useData, useStore } from "../data/store";
import type { ActionState, Incident } from "../data/types";
import { ago, until } from "../format";

const KIND: Record<Incident["kind"], { label: string; icon: "lock" | "alert" | "clock" | "globe" | "spark" }> = {
  blocked_connection: { label: "Blocked", icon: "lock" },
  coverage_lost: { label: "Coverage lost", icon: "alert" },
  telemetry_gap: { label: "Activity gap", icon: "clock" },
  policy_rejected: { label: "Policy rejected", icon: "alert" },
  policy_rolled_back: { label: "Trial rolled back", icon: "clock" },
  dns_blocked: { label: "DNS block", icon: "globe" },
  new_destination: { label: "New destination", icon: "spark" },
};

/** Why an allow-once cannot be offered for this incident, or null when the controller could accept it. */
export function allowOnceUnavailable(i: Incident): string | null {
  if (i.kind !== "blocked_connection") return "Only a blocked connection can be allowed once.";
  if (!i.sessionId) return "Allow once is bound to a verified protected session. Ordinary-app grants stay unavailable until device-scoped app identity is proven (roadmap W03/W07).";
  if (!i.port || i.destination === "rule-scoped" || i.destination === "-") return "This platform recorded a rule-scoped counter, not a destination. Make a reviewed policy change instead.";
  if (i.state === "resolved") return "This incident is resolved.";
  return null;
}

/** The exact permission, rendered from the controller's canonical plan (not from explanatory text). */
function PlanReview({ i, a }: { i: Incident; a: ActionState }) {
  const { approvePlan, cancelPlan, issuer, canAct } = useStore();
  const data = useData();
  const p = a.plan!.plan;
  const dev = data.devices.find((d) => d.id === p.scope.device_id);
  const delegated = !!issuer && p.issuer.role === "delegated" && p.issuer.key_id === issuer.keyId;
  return (
    <div className="plan" aria-label="Exact permission to approve">
      <dl className="facts plan-facts">
        <div>
          <dt>Device</dt>
          <dd>
            <Ident value={dev?.name ?? p.scope.device_id} /> <span className="muted small">(<Ident value={p.scope.device_id} mono />)</span>
          </dd>
        </div>
        <div>
          <dt>{p.scope.kind === "task" ? "Session" : "App"}</dt>
          <dd>{p.scope.kind === "task" ? <Ident value={p.scope.task_id} mono /> : <Ident value={p.scope.executable.path} mono />}</dd>
        </div>
        <div>
          <dt>Destination</dt>
          <dd>
            <Ident value={p.destination.kind === "address" ? p.destination.address : p.destination.hostname} kind="host" mono /> · {p.transport.toUpperCase()} {p.port}
          </dd>
        </div>
        <div>
          <dt>New connections until</dt>
          <dd>
            {new Date(p.admission_until).toLocaleString()} <span className="muted small">({until(p.admission_until)}; retries keep this deadline)</span>
          </dd>
        </div>
        <div>
          <dt>Open connections</dt>
          <dd>{p.stream_policy === "admission_only" ? "Not cut at the deadline (admission only)" : p.stream_policy}</dd>
        </div>
      </dl>
      <div className="small muted">
        {delegated ? <>Signed on this device with its delegated approval key <Ident value={issuer!.keyId} mono />. The signer checks the delegation and this exact plan.</> : "This browser has no delegated approval key for this device; the signer decides whether an owner session may approve."}
      </div>
      <div className="decision-actions">
        <button type="button" className="btn btn-primary" disabled={!canAct.ok} onClick={() => approvePlan(i)}>
          <Icon name="check" size={16} /> Approve exactly this
        </button>
        <button type="button" className="btn btn-quiet" onClick={() => cancelPlan(i)}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function phaseBadge(a: ActionState) {
  const map: Record<ActionState["phase"], [string, string]> = {
    planning: ["blue", "preparing"],
    review: ["amber", "review: not approved yet"],
    sending: ["blue", "sending"],
    pending: ["amber", "pending: no endpoint receipt yet"],
    active: ["green", "active on the endpoint"],
    rejected: ["red", "rejected"],
    failed: ["red", "not sent"],
    expired: ["neutral", "expired"],
    revoked: ["neutral", "revoked"],
    done: ["neutral", "recorded"],
    simulated: ["violet", "demo: simulated"],
  };
  const [tone, label] = map[a.phase];
  return <Badge tone={tone}>{label}</Badge>;
}

export function DecisionCard({ incident: i, go, detailed = false }: { incident: Incident; go: (to: string) => void; detailed?: boolean }) {
  const { allowOnce, keepBlocked, actions, canAct } = useStore();
  const data = useData();
  const device = data.devices.find((d) => d.id === i.deviceId);
  const action = actions[i.id];
  const unavailable = allowOnceUnavailable(i);
  const busy = action?.phase === "sending" || action?.phase === "pending" || action?.phase === "planning";
  const settled = action && !["failed", "rejected"].includes(action.phase);
  return (
    <Card className={`decision ${action ? "decision-acted" : ""}`}>
      <button type="button" className="decision-head" onClick={() => go(`activity/${encodeURIComponent(i.id)}`)}>
        <div className="decision-icon">
          <Icon name="lock" size={18} />
        </div>
        <div className="decision-meta">
          <div className="decision-chain">{i.chain ? <Chain nodes={i.chain} compact complete={i.chainComplete} /> : <Ident value={i.app ?? "unknown app"} />}</div>
          <div className="muted small">
            <Ident value={device?.name ?? i.deviceId} /> · {i.sessionId ? <>session <Ident value={i.sessionId.slice(-6)} mono /></> : "no session"} · {ago(i.lastAt)}
            {i.occurrences > 1 ? ` · ${i.occurrences}×` : ""}
          </div>
        </div>
        {!detailed && <Icon name="chevron" size={16} className="row-chevron" />}
      </button>
      <div className="decision-dest">
        <Ident value={i.destination} kind="host" mono className="dest" />
        <span className="muted">
          {i.protocol ?? (i.port ? `port ${i.port}` : "port not recorded")}
          {i.destinationLabel ? ` · ${i.destinationLabel}` : ""}
        </span>
      </div>
      <p className="decision-text">
        <Ident value={i.explanation} kind="text" />
      </p>
      {action && (
        <div className="decision-progress" aria-live="polite">
          <div className="decision-phase">{phaseBadge(action)}</div>
          {action.phase === "review" && action.plan ? <PlanReview i={i} a={action} /> : <Steps action={action} />}
          {action.error && <div className="small bad">{action.error}</div>}
          {action.kind === "allow_once" && action.expiresAt && action.phase === "active" && <div className="small muted">Expires at its original deadline · {until(action.expiresAt)}. Retries never extend it.</div>}
        </div>
      )}
      {!settled && (
        <div className="decision-actions">
          <button type="button" className="btn btn-primary" disabled={!!unavailable || !canAct.ok || busy} onClick={() => allowOnce(i)} aria-describedby={`why-${i.id}`}>
            <Icon name="check" size={16} /> Allow once for this session
          </button>
          <button type="button" className="btn btn-quiet" disabled={!canAct.ok || busy} onClick={() => keepBlocked(i)}>
            Keep blocked
          </button>
        </div>
      )}
      {!settled && (
        <div className="decision-fine" id={`why-${i.id}`}>
          {unavailable ?? canAct.reason ?? `Only this session on ${device?.name ?? i.deviceId}, this destination, ${i.protocol ?? "this port"}, for 1 hour. Bound to incident revision ${i.revision} and policy revision ${data.policyRevision}; if either changes, the controller refuses it as stale.`}
        </div>
      )}
    </Card>
  );
}

export function Activity({ go }: { go: (to: string) => void }) {
  const data = useData();
  const { actions } = useStore();
  const [filter, setFilter] = useState<"all" | "open" | "blocked" | "gaps">("open");
  const list = data.incidents.filter((i) => (filter === "all" ? true : filter === "open" ? i.state === "open" : filter === "blocked" ? i.kind === "blocked_connection" || i.kind === "dns_blocked" : i.kind === "telemetry_gap" || i.kind === "coverage_lost"));
  return (
    <div className="page">
      <div className="page-head">
        <h1>Activity</h1>
        <p className="lede">Repeated attempts are grouped into one incident by session or app, destination and rule. Notification limits never change what is blocked.</p>
      </div>
      <div className="segmented" role="tablist">
        {(["open", "blocked", "gaps", "all"] as const).map((f) => (
          <button key={f} type="button" role="tab" aria-selected={filter === f} className={filter === f ? "seg active" : "seg"} onClick={() => setFilter(f)}>
            {f === "open" ? "Open" : f === "blocked" ? "Blocked" : f === "gaps" ? "Gaps" : "All"}
          </button>
        ))}
      </div>
      <div className="timeline">
        {list.map((i) => {
          const k = KIND[i.kind];
          const device = data.devices.find((d) => d.id === i.deviceId);
          return (
            <button key={i.id} type="button" className={`tl-item urg-${i.urgency} ${i.state !== "open" ? "tl-quiet" : ""}`} onClick={() => go(`activity/${encodeURIComponent(i.id)}`)}>
              <span className="tl-rail">
                <span className={`tl-icon kind-${i.kind}`}>
                  <Icon name={k.icon} size={14} />
                </span>
              </span>
              <span className="tl-body">
                <span className="tl-top">
                  <span className="tl-kind">{k.label}</span>
                  <span className="muted small">{ago(i.lastAt)}</span>
                </span>
                <span className="tl-title">
                  {i.chain ? <Chain nodes={i.chain} compact /> : <Ident value={device?.name ?? i.deviceId} />}
                  {i.destination !== "-" && (
                    <>
                      {" "}
                      <span className="muted">→</span> <Ident value={i.destination} kind="host" mono />
                    </>
                  )}
                </span>
                <span className="tl-sub muted small">
                  <Ident value={device?.name ?? i.deviceId} /> · <Ident value={i.reason} kind="text" />
                </span>
                <span className="tl-badges">
                  {i.occurrences > 1 && <Badge>{i.occurrences}×</Badge>}
                  {i.state === "acknowledged" && <Badge tone="neutral">acknowledged</Badge>}
                  {i.state === "resolved" && <Badge tone="neutral">resolved</Badge>}
                  {i.kind === "dns_blocked" && <Badge tone="violet">DNS only</Badge>}
                  {actions[i.id] && actions[i.id]!.kind === "allow_once" && actions[i.id]!.phase === "active" && <Badge tone="green">allowed once</Badge>}
                  {actions[i.id] && actions[i.id]!.kind === "allow_once" && actions[i.id]!.phase === "pending" && <Badge tone="amber">allow pending</Badge>}
                </span>
              </span>
            </button>
          );
        })}
        {!list.length && (
          <Empty title="Nothing in this view" icon="activity">
            Blocked connections, coverage changes, rollbacks and telemetry gaps appear here as devices report them.
          </Empty>
        )}
      </div>
    </div>
  );
}

export function IncidentDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { acknowledge, incidentById, actions, canAct } = useStore();
  const data = useData();
  const i = incidentById(id);
  if (!i)
    return (
      <div className="page">
        <button type="button" className="back" onClick={() => go("activity")}>
          <Icon name="chevron" size={16} className="flip" /> Activity
        </button>
        <Empty title="No such incident" icon="alert">
          Nothing with this reference exists in the data this page has. No other incident was opened in its place.
        </Empty>
      </div>
    );
  const decision = i.kind === "blocked_connection" && i.sessionId && i.state !== "resolved";
  const action = actions[i.id];
  return (
    <div className="page">
      <button type="button" className="back" onClick={() => go("activity")}>
        <Icon name="chevron" size={16} className="flip" /> Activity
      </button>
      <div className="page-head">
        <div className="eyebrow">
          {KIND[i.kind].label} · <Ident value={data.devices.find((d) => d.id === i.deviceId)?.name ?? i.deviceId} /> · incident <Ident value={i.id} mono /> rev {i.revision}
        </div>
        <h1 className="detail-title">{i.destination !== "-" ? <Ident value={i.destination} kind="host" mono /> : <Ident value={i.reason} kind="text" />}</h1>
      </div>
      {decision ? (
        <DecisionCard incident={i} go={go} detailed />
      ) : (
        <Card>
          <p className="decision-text">
            <Ident value={i.explanation} kind="text" />
          </p>
          {action && <Steps action={action} />}
          {action?.error && <div className="small bad">{action.error}</div>}
          {i.state === "open" && (
            <>
              <button type="button" className="btn btn-quiet" disabled={!canAct.ok || action?.phase === "sending"} onClick={() => acknowledge(i)}>
                Acknowledge
              </button>
              <div className="muted small">{canAct.reason ?? "Acknowledge means seen. It never allows anything; a new occurrence reopens the incident."}</div>
            </>
          )}
        </Card>
      )}
      <div className="grid-2">
        {i.chain && (
          <Card>
            <SectionTitle action={<Badge tone={i.chainComplete ? "green" : "amber"}>{i.chainComplete ? "lifecycle intact" : "incomplete"}</Badge>}>Process chain</SectionTitle>
            <Chain nodes={i.chain} complete={i.chainComplete} />
          </Card>
        )}
        <Card>
          <SectionTitle>Evidence</SectionTitle>
          <dl className="facts">
            <div>
              <dt>Decision</dt>
              <dd>
                <Ident value={i.reason} kind="text" />
              </dd>
            </div>
            {i.policyRevision && (
              <div>
                <dt>Policy</dt>
                <dd>revision {i.policyRevision}</dd>
              </div>
            )}
            <div>
              <dt>Transfer</dt>
              <dd>{i.measurement}</dd>
            </div>
            {i.facts.map((f) => (
              <div key={f.label}>
                <dt>{f.label}</dt>
                <dd>
                  <Ident value={f.value} kind="text" />
                  {f.source && <span className="fact-src">{f.source}</span>}
                </dd>
              </div>
            ))}
            <div>
              <dt>Seen</dt>
              <dd>
                {i.occurrences}× · first {ago(i.firstAt)} · last {ago(i.lastAt)}
              </dd>
            </div>
          </dl>
        </Card>
      </div>
      <p className="footnote">Explanations are deterministic templates over recorded fields. Region labels come from documented endpoint names and do not identify who operates a bucket.</p>
    </div>
  );
}
