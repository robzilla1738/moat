import { Badge, Card, Chain, Icon, SectionTitle } from "../components/ui";
import { useStore } from "../data/store";
import { ago } from "../format";

export function Sessions({ go }: { go: (to: string) => void }) {
  const { data } = useStore();
  return (
    <div className="page">
      <div className="page-head">
        <h1>Sessions</h1>
        <p className="lede">Runs started through a protected launcher. The boundary exists before the first instruction executes, and every child inherits it.</p>
      </div>
      <div className="stack">
        {data.sessions.map((s) => {
          const device = data.devices.find((d) => d.id === s.deviceId);
          return (
            <Card key={s.id} as="button" onClick={() => go(`sessions/${s.id}`)} className="session-card">
              <div className="session-top">
                <div>
                  <div className="session-title">{s.chain[0]?.name ?? s.id}</div>
                  <div className="muted small">
                    {device?.name} · {s.profile} · {s.state === "running" ? `running ${ago(s.startedAt).replace(" ago", "")}` : `ended ${ago(s.endedAt ?? s.startedAt)}`}
                  </div>
                </div>
                {s.boundaryKind === "linux_cgroup" && s.verified ? <Badge tone="green" dot>Protected</Badge> : <Badge tone="amber">Instrumented only</Badge>}
              </div>
              <div className="session-boundary">
                <Icon name={s.boundaryKind === "linux_cgroup" ? "shield" : "alert"} size={14} />
                <span>{s.boundary}</span>
              </div>
              {s.chain.length > 1 && (
                <div className="session-chain">
                  <Chain nodes={s.chain} compact />
                </div>
              )}
              <div className="session-counts">
                <span>
                  <span className="ok">{s.allowed.reduce((a, b) => a + b.count, 0)}</span> allowed
                </span>
                <span>
                  <span className="bad">{s.blocked.reduce((a, b) => a + b.count, 0)}</span> blocked
                </span>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export function SessionDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { data } = useStore();
  const s = data.sessions.find((x) => x.id === id);
  if (!s) return <div className="page">Not found</div>;
  const device = data.devices.find((d) => d.id === s.deviceId);
  return (
    <div className="page">
      <button type="button" className="back" onClick={() => go("sessions")}>
        <Icon name="chevron" size={16} className="flip" /> Sessions
      </button>
      <div className="page-head">
        <div className="eyebrow">
          {device?.name} · {s.profile}
        </div>
        <h1 className="detail-title">{s.chain[0]?.name}</h1>
        <div className="head-badges">
          {s.verified ? <Badge tone="green" dot>Verified session</Badge> : <Badge tone="amber">Self-reported; a hint only</Badge>}
          <Badge tone={s.state === "running" ? "blue" : "neutral"}>{s.state}</Badge>
          <span className="mono small muted">{s.id}</span>
        </div>
      </div>
      <Card className="boundary-card">
        <div className="boundary-row">
          <Icon name={s.boundaryKind === "linux_cgroup" ? "shield" : "alert"} size={20} />
          <div>
            <div className="boundary-title">{s.boundary}</div>
            <div className="muted small">
              {s.boundaryKind === "linux_cgroup"
                ? "Placed in its cgroup before exec, uid dropped, no_new_privs, inherited descriptors closed, user-session brokers hidden. Not covered: abstract Unix sockets, the system DNS resolver, loopback services the profile allows."
                : "A label without an OS boundary. Session rules do not apply; traffic follows the ordinary profile."}
            </div>
          </div>
        </div>
        <div className="muted small">Launched by {s.launcher} · started {ago(s.startedAt)}</div>
      </Card>
      <div className="grid-2">
        <Card>
          <SectionTitle>Process chain</SectionTitle>
          <Chain nodes={s.chain} />
        </Card>
        <Card>
          <SectionTitle>Destinations</SectionTitle>
          <ul className="dest-list">
            {s.allowed.map((a) => (
              <li key={a.destination}>
                <span className="dest-verdict ok">
                  <Icon name="check" size={12} />
                </span>
                <span className="mono">{a.destination}</span>
                <span className="muted small">{a.via}</span>
                <span className="dest-count">{a.count}</span>
              </li>
            ))}
            {s.blocked.map((a) => (
              <li key={a.destination}>
                <span className="dest-verdict bad">
                  <Icon name="x" size={12} />
                </span>
                <span className="mono">{a.destination}</span>
                <span className="muted small">{a.rule}</span>
                <span className="dest-count">{a.count}</span>
              </li>
            ))}
            {!s.allowed.length && !s.blocked.length && <li className="muted">No attributed flows.</li>}
          </ul>
        </Card>
      </div>
      {s.intent && (
        <Card>
          <SectionTitle action={<Badge>self-reported</Badge>}>Stated intent</SectionTitle>
          <p className="intent">“{s.intent}”</p>
          <div className="muted small">Reported by the agent. It enriches the timeline; it cannot grant access or confirm a block.</div>
        </Card>
      )}
      {s.state === "running" && (
        <div className="decision-actions">
          <button type="button" className="btn btn-danger">
            End session
          </button>
          <span className="muted small">Sent as a typed close action on the device's next sync; done when the endpoint reports it ended.</span>
        </div>
      )}
    </div>
  );
}
