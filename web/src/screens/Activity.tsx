import { useState } from "react";
import { Badge, Card, Chain, Icon, SectionTitle, Steps } from "../components/ui";
import { useStore } from "../data/store";
import type { Incident } from "../data/types";
import { ago, until } from "../format";

const KIND: Record<Incident["kind"], { label: string; icon: "lock" | "alert" | "clock" | "globe" | "spark" }> = {
  blocked_connection: { label: "Blocked", icon: "lock" },
  coverage_lost: { label: "Coverage lost", icon: "alert" },
  telemetry_gap: { label: "Activity gap", icon: "clock" },
  policy_rejected: { label: "Policy rejected", icon: "alert" },
  dns_blocked: { label: "DNS block", icon: "globe" },
  new_destination: { label: "New destination", icon: "spark" },
};

export function DecisionCard({ incident: i, go, detailed = false }: { incident: Incident; go: (to: string) => void; detailed?: boolean }) {
  const { allowOnce, keepBlocked, data } = useStore();
  const device = data.devices.find((d) => d.id === i.deviceId);
  const pending = i.action && i.action.steps.some((s) => s.state !== "done");
  return (
    <Card className={`decision ${i.action ? "decision-acted" : ""}`}>
      <button type="button" className="decision-head" onClick={() => go(`activity/${i.id}`)}>
        <div className="decision-icon">
          <Icon name="lock" size={18} />
        </div>
        <div className="decision-meta">
          <div className="decision-chain">{i.chain ? <Chain nodes={i.chain} compact complete={i.chainComplete} /> : i.app}</div>
          <div className="muted small">
            {device?.name} · {i.sessionId ? `session ${i.sessionId.slice(-6)}` : "no session"} · {ago(i.lastAt)}
            {i.occurrences > 1 ? ` · ${i.occurrences}×` : ""}
          </div>
        </div>
        {!detailed && <Icon name="chevron" size={16} className="row-chevron" />}
      </button>
      <div className="decision-dest">
        <span className="mono dest">{i.destination}</span>
        <span className="muted">
          {i.protocol ?? `port ${i.port}`}
          {i.destinationLabel ? ` · ${i.destinationLabel}` : ""}
        </span>
      </div>
      <p className="decision-text">{i.explanation}</p>
      {i.action ? (
        <div className="decision-progress">
          <Steps action={i.action} />
          {i.action.kind === "allow_once" && i.action.expiresAt && !pending && <div className="small muted">Expires on its own · {until(i.action.expiresAt)}</div>}
        </div>
      ) : (
        <div className="decision-actions">
          <button type="button" className="btn btn-primary" onClick={() => allowOnce(i.id)}>
            <Icon name="check" size={16} /> Allow once for this session
          </button>
          <button type="button" className="btn btn-quiet" onClick={() => keepBlocked(i.id)}>
            Keep blocked
          </button>
        </div>
      )}
      {!i.action && <div className="decision-fine">Only this session, this destination, {i.protocol ?? "this port"}, for 1 hour. Bound to policy rev {i.policyRevision}; a newer revision makes this button stale.</div>}
    </Card>
  );
}

export function Activity({ go }: { go: (to: string) => void }) {
  const { data } = useStore();
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
            <button key={i.id} type="button" className={`tl-item urg-${i.urgency} ${i.state !== "open" ? "tl-quiet" : ""}`} onClick={() => go(`activity/${i.id}`)}>
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
                  {i.chain ? <Chain nodes={i.chain} compact /> : device?.name}
                  {i.destination !== "-" && (
                    <>
                      {" "}
                      <span className="muted">→</span> <span className="mono">{i.destination}</span>
                    </>
                  )}
                </span>
                <span className="tl-sub muted small">
                  {device?.name} · {i.reason}
                </span>
                <span className="tl-badges">
                  {i.occurrences > 1 && <Badge>{i.occurrences}×</Badge>}
                  {i.state === "acknowledged" && <Badge tone="neutral">acknowledged</Badge>}
                  {i.state === "resolved" && <Badge tone="neutral">resolved</Badge>}
                  {i.kind === "dns_blocked" && <Badge tone="violet">DNS only</Badge>}
                  {i.action?.kind === "allow_once" && <Badge tone="green">allowed once</Badge>}
                </span>
              </span>
            </button>
          );
        })}
        {!list.length && <div className="empty">Nothing here.</div>}
      </div>
    </div>
  );
}

export function IncidentDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { data, acknowledge } = useStore();
  const i = data.incidents.find((x) => x.id === id);
  if (!i) return <div className="page">Not found</div>;
  const decision = i.kind === "blocked_connection" && i.sessionId && i.state !== "resolved";
  return (
    <div className="page">
      <button type="button" className="back" onClick={() => go("activity")}>
        <Icon name="chevron" size={16} className="flip" /> Activity
      </button>
      <div className="page-head">
        <div className="eyebrow">
          {KIND[i.kind].label} · {data.devices.find((d) => d.id === i.deviceId)?.name}
        </div>
        <h1 className="detail-title">{i.destination !== "-" ? <span className="mono">{i.destination}</span> : i.reason}</h1>
      </div>
      {decision ? (
        <DecisionCard incident={i} go={go} detailed />
      ) : (
        <Card>
          <p className="decision-text">{i.explanation}</p>
          {i.state === "open" && (
            <button type="button" className="btn btn-quiet" onClick={() => acknowledge(i.id)}>
              Acknowledge
            </button>
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
              <dd>{i.reason}</dd>
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
                  {f.value}
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
