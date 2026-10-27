/**
 * Tasks ("What are my protected tasks doing?") and one task. A task is something you start through Moat (for example
 * a coding agent) that runs inside a boundary with its own rules. Whether that boundary is real is always visible.
 */
import { Actions, Button, Card, Chain, Details, EmptyState, Facts, Fine, Icon, Ident, List, ListRow, Page, Stat, StatusChip } from "../components/ui";
import { useData, useStore } from "../data/store";
import type { Session } from "../data/types";
import { ago } from "../format";

const sum = (xs: { count: number }[]) => xs.reduce((a, b) => a + b.count, 0);
const isProtected = (s: Session) => s.boundaryKind === "linux_cgroup" && s.verified;

function TaskChip({ s }: { s: Session }) {
  return isProtected(s) ? (
    <StatusChip tone="green" icon="lock">
      Protected
    </StatusChip>
  ) : (
    <StatusChip tone="amber">Not protected: label only</StatusChip>
  );
}

export function Sessions({ go }: { go: (to: string) => void }) {
  const data = useData();
  return (
    <Page title="Tasks" lede="Things you start through Moat, such as a coding agent. Each runs inside its own boundary with its own rules.">
      {data.sessions.length === 0 ? (
        <EmptyState title="No tasks yet" icon="sessions">
          Start an app with moat-launch on a Linux computer and it shows up here, with everything it tried to reach.
        </EmptyState>
      ) : (
        <div className="card list-card">
          {data.sessions.map((s) => {
            const device = data.devices.find((d) => d.id === s.deviceId);
            return (
              <ListRow
                key={s.id}
                icon={<Icon name="sessions" size={16} />}
                title={<Ident value={s.chain[0]?.name ?? s.id} />}
                sub={
                  <>
                    <Ident value={device?.name ?? s.deviceId} /> · {s.state === "running" ? `running for ${ago(s.startedAt).replace(" ago", "")}` : `ended ${ago(s.endedAt ?? s.startedAt)}`} · {sum(s.allowed)} allowed · {sum(s.blocked)} blocked
                  </>
                }
                trailing={<TaskChip s={s} />}
                onClick={() => go(`sessions/${encodeURIComponent(s.id)}`)}
              />
            );
          })}
        </div>
      )}
    </Page>
  );
}

export function SessionDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const data = useData();
  const { closeSession, canAct } = useStore();
  const s = data.sessions.find((x) => x.id === id);
  void go;
  if (!s)
    return (
      <Page title="Task not found" back={{ label: "Tasks", to: "sessions" }}>
        <EmptyState title="Task not found" icon="sessions" />
      </Page>
    );
  const device = data.devices.find((d) => d.id === s.deviceId);
  return (
    <Page back={{ label: "Tasks", to: "sessions" }} eyebrow={<Ident value={device?.name ?? s.deviceId} />} title={<Ident value={s.chain[0]?.name ?? s.id} />}>
      <div className="chips">
        <TaskChip s={s} />
        <StatusChip tone={s.state === "running" ? "blue" : "neutral"}>{s.state === "running" ? "Running" : "Ended"}</StatusChip>
        {!s.verified && <StatusChip tone="amber">Reported by the app itself</StatusChip>}
      </div>
      <Card title={isProtected(s) ? "Protected from the start" : "Not protected"}>
        <p>{isProtected(s) ? "Moat set up this task's boundary before it started, and everything it launches stays inside." : "This is only a label. No boundary was set up, so the task follows the device's normal rules."}</p>
        <Details summary="Technical details">
          <Facts
            rows={[
              ["Boundary", <Ident key="b" value={s.boundary} kind="text" />],
              ["Task id", <Ident key="i" value={s.id} mono />],
              ["Rules", <Ident key="p" value={s.profile} />],
              ["Started by", `${s.launcher} · ${ago(s.startedAt)}`],
            ]}
          />
          {s.boundaryKind === "linux_cgroup" && <Fine>Placed in its cgroup before exec, uid dropped, no_new_privs, inherited descriptors closed, user-session brokers hidden. Not covered: abstract Unix sockets, the system DNS resolver, loopback services the profile allows.</Fine>}
          {s.chain.length > 0 && <Chain nodes={s.chain} />}
        </Details>
      </Card>
      <Card title="Where it connected">
        <div className="stats">
          <Stat label="Allowed" value={sum(s.allowed)} tone="green" />
          <Stat label="Blocked" value={sum(s.blocked)} tone="red" />
        </div>
        <List>
          {s.blocked.map((a) => (
            <ListRow key={`b${a.destination}`} title={<Ident value={a.destination} kind="host" mono />} sub={<Ident value={a.rule} kind="text" />} trailing={<StatusChip tone="red">{a.count} blocked</StatusChip>} />
          ))}
          {s.allowed.map((a) => (
            <ListRow key={`a${a.destination}`} title={<Ident value={a.destination} kind="host" mono />} sub={<Ident value={a.via} kind="text" />} trailing={<StatusChip tone="green">{a.count} allowed</StatusChip>} />
          ))}
          {!s.allowed.length && !s.blocked.length && <p className="muted">Nothing recorded for this task yet.</p>}
        </List>
      </Card>
      {s.intent && (
        <Card title="What the app said it was doing" action={<StatusChip>Its own words</StatusChip>}>
          <p className="intent">
            &ldquo;<Ident value={s.intent} kind="text" />&rdquo;
          </p>
          <Fine>The app reported this itself. It helps you read the activity; it can&apos;t allow anything or prove a block.</Fine>
        </Card>
      )}
      {s.state === "running" && (
        <Card>
          <Actions>
            <Button kind="danger" disabled={!canAct.ok || !!s.closeRequestedAt} onClick={() => closeSession(s)}>
              {s.closeRequestedAt ? "End requested" : "End this task"}
            </Button>
          </Actions>
          <Fine>{canAct.reason ?? (s.closeRequestedAt ? `Requested ${ago(s.closeRequestedAt)}. It keeps running until the device confirms it ended.` : "Sent to the device when it next checks in. Done when the device confirms it ended.")}</Fine>
        </Card>
      )}
    </Page>
  );
}
