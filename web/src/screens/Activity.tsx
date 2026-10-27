/**
 * Activity ("What happened, and is any of it a problem?") and the decision card ("Should I allow this?").
 * Plain words first; hostnames stay visible because they are what you decide on, and everything else technical
 * (task id, port, rule and alert versions, the program chain) sits under Details.
 */
import { useState } from "react";
import { Actions, Button, Card, Chain, Details, EmptyState, Facts, Fine, Icon, Ident, Page, StatusChip, Steps, type IconName, type Tone } from "../components/ui";
import { useData, useStore } from "../data/store";
import type { ActionState, Incident } from "../data/types";
import { ago, until } from "../format";

export const KIND: Record<Incident["kind"], { label: string; icon: IconName; tone: Tone }> = {
  blocked_connection: { label: "Blocked", icon: "lock", tone: "red" },
  coverage_lost: { label: "Protection lost", icon: "alert", tone: "red" },
  telemetry_gap: { label: "Gap in reports", icon: "clock", tone: "amber" },
  policy_rejected: { label: "Rule change refused", icon: "alert", tone: "amber" },
  policy_rolled_back: { label: "Trial change undone", icon: "undo", tone: "amber" },
  dns_blocked: { label: "Blocked by web filter", icon: "globe", tone: "violet" },
  new_destination: { label: "New place", icon: "spark", tone: "blue" },
  recovery_required: { label: "Needs you at the device", icon: "wrench", tone: "red" },
  rollback_pending: { label: "Undo didn't finish", icon: "undo", tone: "red" },
  session_not_adopted: { label: "Task stopped after restart", icon: "clock", tone: "amber" },
  proxy_limit: { label: "Limit reached", icon: "alert", tone: "amber" },
};

/** The app a person would recognise: the start of the program chain ("Claude Code"), else the app the device named. */
export function appOf(i: Incident): string {
  return i.chain?.[0]?.name ?? i.app ?? "an unknown app";
}

/** Why an allow-once cannot be offered for this alert, or null when the controller could accept it. */
export function allowOnceUnavailable(i: Incident): string | null {
  if (i.kind !== "blocked_connection") return "Only a blocked connection can be allowed once.";
  if (!i.sessionId) return "Allow once only works inside a protected task for now. For other apps it stays off until Moat can prove the app on the device (roadmap W03/W07).";
  if (!i.port || i.destination === "rule-scoped" || i.destination === "-") return "This device only recorded which rule matched (rule-scoped), not the address. Change your rules instead.";
  if (i.state === "resolved") return "This is already resolved.";
  return null;
}

/** The exact permission, rendered from the controller's canonical plan (not from explanatory text). Always visible. */
function PlanReview({ i, a }: { i: Incident; a: ActionState }) {
  const { approvePlan, cancelPlan, issuer, canAct } = useStore();
  const data = useData();
  const p = a.plan!.plan;
  const dev = data.devices.find((d) => d.id === p.scope.device_id);
  const delegated = !!issuer && p.issuer.role === "delegated" && p.issuer.key_id === issuer.keyId;
  return (
    <div className="plan" aria-label="Exact permission to approve">
      <Facts
        rows={[
          [
            "Device",
            <>
              <Ident value={dev?.name ?? p.scope.device_id} /> <span className="muted">(<Ident value={p.scope.device_id} mono />)</span>
            </>,
          ],
          [p.scope.kind === "task" ? "Task" : "App", p.scope.kind === "task" ? <Ident value={p.scope.task_id} mono /> : <Ident value={p.scope.executable.path} mono />],
          [
            "Address",
            <>
              <Ident value={p.destination.kind === "address" ? p.destination.address : p.destination.hostname} kind="host" mono /> · {p.transport.toUpperCase()} {p.port}
            </>,
          ],
          [
            "New connections until",
            <>
              {new Date(p.admission_until).toLocaleString()} <span className="muted">({until(p.admission_until)}; trying again doesn&apos;t extend it)</span>
            </>,
          ],
          ["Already open", p.stream_policy === "admission_only" ? "Connections already open stay open after this time" : p.stream_policy],
        ]}
      />
      <Fine>
        {delegated ? (
          <>
            Signed on this device with its approval key <Ident value={issuer!.keyId} mono />. The controller checks the key and this exact permission.
          </>
        ) : (
          "This browser has no approval key for this device; the controller decides whether your sign-in may approve."
        )}
      </Fine>
      <Actions>
        <Button kind="primary" icon="check" disabled={!canAct.ok} onClick={() => approvePlan(i)}>
          Approve exactly this
        </Button>
        <Button kind="quiet" onClick={() => cancelPlan(i)}>
          Cancel
        </Button>
      </Actions>
    </div>
  );
}

const PHASE: Record<ActionState["phase"], [Tone, string]> = {
  planning: ["blue", "Preparing"],
  review: ["amber", "Not approved yet"],
  sending: ["blue", "Sending"],
  pending: ["amber", "Waiting for the device to confirm"],
  active: ["green", "Active on the device"],
  rejected: ["red", "Refused"],
  failed: ["red", "Not sent"],
  expired: ["neutral", "Expired"],
  revoked: ["neutral", "Withdrawn"],
  done: ["neutral", "Saved"],
  simulated: ["violet", "Demo: nothing sent"],
};

/** "Should I allow this?" One decision, two buttons, the exact scope in one sentence; the rest under Details. */
export function DecisionCard({ incident: i, go, detailed = false }: { incident: Incident; go: (to: string) => void; detailed?: boolean }) {
  const { allowOnce, keepBlocked, actions, canAct } = useStore();
  const data = useData();
  const device = data.devices.find((d) => d.id === i.deviceId);
  const action = actions[i.id];
  const unavailable = allowOnceUnavailable(i);
  const busy = action?.phase === "sending" || action?.phase === "pending" || action?.phase === "planning";
  const settled = action && !["failed", "rejected"].includes(action.phase);
  const head = (
    <>
      <span className="decision-icon" aria-hidden>
        <Icon name="lock" size={18} />
      </span>
      <span className="decision-meta">
        <span className="decision-title">
          Blocked <Ident value={appOf(i)} /> from connecting
        </span>
        <span className="row-sub">
          <Ident value={device?.name ?? i.deviceId} /> · {ago(i.lastAt)}
          {i.occurrences > 1 ? ` · ${i.occurrences} times` : ""}
        </span>
      </span>
    </>
  );
  return (
    <Card className={`decision ${detailed ? "" : "decision-summary"} ${action ? "decision-acted" : ""}`}>
      {detailed ? (
        <div className="decision-head">{head}</div>
      ) : (
        <button type="button" className="decision-head decision-head-link" onClick={() => go(`activity/${encodeURIComponent(i.id)}`)}>
          {head}
          <Icon name="chevron" size={16} className="row-chevron" />
        </button>
      )}
      <div className="decision-dest">
        <span className="muted">To</span> <Ident value={i.destination} kind="host" mono className="dest" />
        {i.destinationLabel && (
          <span className="muted">
            {" "}
            · <Ident value={i.destinationLabel} kind="text" />
          </span>
        )}
      </div>
      <p className="decision-text">
        <Ident value={i.explanation} kind="text" />
      </p>
      {action && (
        <div className="decision-progress" aria-live="polite">
          <StatusChip tone={PHASE[action.phase][0]}>{PHASE[action.phase][1]}</StatusChip>
          {action.phase === "review" && action.plan ? <PlanReview i={i} a={action} /> : <Steps action={action} />}
          {action.error && <p className="error">{action.error}</p>}
          {action.kind === "allow_once" && action.expiresAt && action.phase === "active" && <Fine>Ends on its own at the original time · {until(action.expiresAt)}. Trying again never extends it.</Fine>}
        </div>
      )}
      {!settled && (
        <>
          <Actions>
            <Button kind="primary" icon="check" disabled={!!unavailable || !canAct.ok || busy} onClick={() => allowOnce(i)} describedBy={`why-${i.id}`}>
              Allow once for this task
            </Button>
            <Button kind="secondary" disabled={!canAct.ok || busy} onClick={() => keepBlocked(i)}>
              Keep blocking
            </Button>
          </Actions>
          <Fine id={`why-${i.id}`}>{unavailable ?? canAct.reason ?? `Only this task on ${device?.name ?? i.deviceId}, only this address, for 1 hour. If your rules change first, Moat refuses it as out of date.`}</Fine>
        </>
      )}
      <Details summary="Technical details">
        <Facts
          rows={[
            ...(i.chain ? ([["Started by", <Chain key="c" nodes={i.chain} compact complete={i.chainComplete} />]] as [string, JSX.Element][]) : []),
            ["Task", i.sessionId ? <Ident value={i.sessionId} mono /> : "none"],
            ["Connection", i.protocol ?? (i.port ? `port ${i.port}` : "port not recorded")],
            ["Why it was blocked", <Ident key="r" value={i.reason} kind="text" />],
            ["Bound to", `alert version ${i.revision} and rule version ${data.policyRevision}`],
          ]}
        />
      </Details>
    </Card>
  );
}

const GAP_KINDS: Incident["kind"][] = ["telemetry_gap", "coverage_lost", "recovery_required", "rollback_pending", "session_not_adopted", "proxy_limit"];

/** One alert as a sentence. Hostnames and app names go through Ident (untrusted); the rest is Moat's own words. */
export function AlertTitle({ i, deviceName }: { i: Incident; deviceName: string }) {
  if (i.kind === "blocked_connection")
    return (
      <>
        Blocked <Ident value={appOf(i)} /> from connecting
      </>
    );
  if (i.kind === "dns_blocked")
    return (
      <>
        Blocked a website on <Ident value={deviceName} />
      </>
    );
  return (
    <>
      {KIND[i.kind].label} on <Ident value={deviceName} />
    </>
  );
}

export function Activity({ go }: { go: (to: string) => void }) {
  const data = useData();
  const { actions } = useStore();
  const [filter, setFilter] = useState<"all" | "open" | "blocked" | "gaps">("open");
  const list = data.incidents.filter((i) => (filter === "all" ? true : filter === "open" ? i.state === "open" : filter === "blocked" ? i.kind === "blocked_connection" || i.kind === "dns_blocked" : GAP_KINDS.includes(i.kind)));
  return (
    <Page title="Activity" lede="What Moat blocked or noticed, newest first. Repeats are grouped into one line.">
      <div className="segmented" role="tablist" aria-label="Show">
        {(["open", "blocked", "gaps", "all"] as const).map((f) => (
          <button key={f} type="button" role="tab" aria-selected={filter === f} className={filter === f ? "seg active" : "seg"} onClick={() => setFilter(f)}>
            {f === "open" ? "Needs a look" : f === "blocked" ? "Blocked" : f === "gaps" ? "Gaps" : "All"}
          </button>
        ))}
      </div>
      {list.length ? (
        <div className="card list-card">
          {list.map((i) => {
            const k = KIND[i.kind];
            const device = data.devices.find((d) => d.id === i.deviceId);
            const a = actions[i.id];
            return (
              <button key={i.id} type="button" className={`row row-link ${i.state !== "open" ? "row-quiet" : ""}`} onClick={() => go(`activity/${encodeURIComponent(i.id)}`)}>
                <span className={`row-icon tone-${k.tone}`} aria-hidden>
                  <Icon name={k.icon} size={16} />
                </span>
                <span className="row-main">
                  <span className="row-title">
                    <AlertTitle i={i} deviceName={device?.name ?? i.deviceId} />
                  </span>
                  <span className="row-sub">
                    {i.destination !== "-" ? (
                      <>
                        to <Ident value={i.destination} kind="host" mono /> · <Ident value={device?.name ?? i.deviceId} /> · {ago(i.lastAt)}
                      </>
                    ) : (
                      <>
                        <Ident value={i.reason} kind="text" /> · {ago(i.lastAt)}
                      </>
                    )}
                  </span>
                  {(i.occurrences > 1 || i.state !== "open" || (a && a.kind === "allow_once")) && (
                    <span className="row-chips">
                      {i.occurrences > 1 && <StatusChip>{i.occurrences} times</StatusChip>}
                      {i.state === "acknowledged" && <StatusChip>Seen</StatusChip>}
                      {i.state === "resolved" && <StatusChip>Resolved</StatusChip>}
                      {a && a.kind === "allow_once" && a.phase === "active" && <StatusChip tone="green">Allowed once</StatusChip>}
                      {a && a.kind === "allow_once" && a.phase === "pending" && <StatusChip tone="amber">Allow waiting</StatusChip>}
                    </span>
                  )}
                </span>
                <Icon name="chevron" size={16} className="row-chevron" />
              </button>
            );
          })}
        </div>
      ) : (
        <EmptyState title={filter === "open" ? "Nothing needs a look" : "Nothing here"} icon="activity">
          Blocked connections, gaps in reports and changes in protection show up here as your devices report them.
        </EmptyState>
      )}
    </Page>
  );
}

export function IncidentDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { acknowledge, incidentById, actions, canAct } = useStore();
  const data = useData();
  const i = incidentById(id);
  if (!i)
    return (
      <Page title="Not found" back={{ label: "Activity", to: "activity" }}>
        <EmptyState title="Nothing to show" icon="alert">
          This alert isn&apos;t in what Moat has. Nothing else was opened in its place.
        </EmptyState>
      </Page>
    );
  const decision = i.kind === "blocked_connection" && i.sessionId && i.state !== "resolved";
  const action = actions[i.id];
  const deviceName = data.devices.find((d) => d.id === i.deviceId)?.name ?? i.deviceId;
  return (
    <Page
      back={{ label: "Activity", to: "activity" }}
      eyebrow={
        <>
          {KIND[i.kind].label} · <Ident value={deviceName} />
        </>
      }
      title={i.destination !== "-" ? <Ident value={i.destination} kind="host" mono /> : <AlertTitle i={i} deviceName={deviceName} />}
      titleMono={i.destination !== "-"}
    >
      {decision ? (
        <DecisionCard incident={i} go={go} detailed />
      ) : (
        <Card title={<AlertTitle i={i} deviceName={deviceName} />}>
          <p className="decision-text">
            <Ident value={i.explanation} kind="text" />
          </p>
          {action && <Steps action={action} />}
          {action?.error && <p className="error">{action.error}</p>}
          {i.state === "open" && (
            <>
              <Actions>
                <Button disabled={!canAct.ok || action?.phase === "sending"} onClick={() => acknowledge(i)}>
                  Mark as seen
                </Button>
              </Actions>
              <Fine>{canAct.reason ?? "Marking as seen never allows anything. If it happens again, it comes back."}</Fine>
            </>
          )}
        </Card>
      )}
      <Card title="What Moat recorded">
        <Facts
          rows={[
            ["When", `${i.occurrences} ${i.occurrences === 1 ? "time" : "times"} · first ${ago(i.firstAt)} · last ${ago(i.lastAt)}`],
            ["Data sent", <Ident key="m" value={i.measurement} kind="text" />],
          ]}
        />
        <Details summary="Technical details">
          {i.chain && (
            <>
              <div className="details-label">Program chain {i.chainComplete ? "" : "(incomplete)"}</div>
              <Chain nodes={i.chain} complete={i.chainComplete} />
            </>
          )}
          <Facts
            rows={[
              ["Decision", <Ident key="r" value={i.reason} kind="text" />],
              ...(i.policyRevision ? ([["Rule version", String(i.policyRevision)]] as [string, string][]) : []),
              ["Alert", <span key="a"><Ident value={i.id} mono /> · version {i.revision}</span>],
              ...i.facts.map(
                (f) =>
                  [
                    f.label,
                    <span key={f.label}>
                      <Ident value={f.value} kind="text" />
                      {f.source && <span className="muted"> · {f.source}</span>}
                    </span>,
                  ] as [string, JSX.Element],
              ),
            ]}
          />
          <Fine>Explanations are fixed templates over what the device recorded. Region names come from the server&apos;s published name and don&apos;t say who runs it.</Fine>
        </Details>
      </Card>
    </Page>
  );
}
