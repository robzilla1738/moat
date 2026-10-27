import { Badge, Bars, Card, Chain, CoverageBadge, DeviceIcon, Icon, Ident, SectionTitle, Stat } from "../components/ui";
import { useData, useFreshness } from "../data/store";
import { ago, compact } from "../format";
import { DecisionCard } from "./Activity";

function greeting(h = new Date().getHours()) {
  return h < 12 ? "Morning" : h < 18 ? "Afternoon" : "Evening";
}

export function Home({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const decisions = data.incidents.filter((i) => i.state === "open" && i.kind === "blocked_connection" && i.sessionId);
  const attention = data.incidents.filter((i) => i.state === "open" && i.kind !== "blocked_connection" && i.urgency !== "low");
  const covered = data.devices.filter((d) => !["degraded", "unknown"].includes(fresh(d).coverage)).length;
  const blocked = data.timeline.reduce((s, p) => s + p.blocked, 0);
  const latest = data.revisions[0];
  const applied = latest ? latest.devices.filter((d) => d.states.some((s) => s.state === "applied" || s.state === "confirmed")).length : 0;

  return (
    <div className="page">
      <div className="hero">
        <div className="hero-eyebrow">
          <span className="pulse" /> {greeting()}
          {data.viewer?.name ? `, ${data.viewer.name}` : ""}
        </div>
        <h1 className="hero-title">
          {decisions.length ? (
            <>
              {decisions.length} {decisions.length === 1 ? "decision" : "decisions"} waiting.
              <span className="hero-dim"> Everything else is holding.</span>
            </>
          ) : (
            <>All quiet.</>
          )}
        </h1>
        <div className="hero-stats">
          <Stat label="Covered" value={`${covered}/${data.devices.length}`} sub={<span>{data.devices.filter((d) => d.coverage === "dns-only").length} DNS-only</span>} />
          <Stat label="Blocked 24h" value={compact(blocked)} sub="on device" tone="red" />
          <Stat label="Protected" value={data.sessions.filter((s) => s.state === "running" && s.verified).length} sub="sessions now" tone="green" />
        </div>
      </div>

      {decisions.length > 0 && (
        <>
          <SectionTitle action={<a href="#/activity" className="link">All activity</a>}>Needs a decision</SectionTitle>
          <div className="stack">
            {decisions.slice(0, 2).map((i) => (
              <DecisionCard key={i.id} incident={i} go={go} />
            ))}
          </div>
        </>
      )}

      <div className="grid-2">
        <Card>
          <SectionTitle action={<span className="muted small">last 24 h</span>}>Blocked attempts</SectionTitle>
          <Bars points={data.timeline} />
          <div className="legend">
            <span>
              <span className="legend-swatch" /> blocked by policy
            </span>
            <span className="muted">Observation-only traffic is permitted, not counted here.</span>
          </div>
        </Card>
        <Card as="button" onClick={() => go("rules")}>
          <SectionTitle action={latest ? <Badge tone="blue">rev {latest.revision}</Badge> : undefined}>What changed</SectionTitle>
          {!latest && <div className="muted small">No policy revision has been signed yet.</div>}
          {latest && (
            <>
              <div className="change-title">
                <Ident value={latest.title} kind="text" />
              </div>
              <div className="muted small">
                <Ident value={latest.author} /> · {ago(latest.createdAt)} · {latest.authorizedBy === "owner_key" ? "signed with an owner key" : latest.authorizedBy === "narrowing" ? "narrowing change" : latest.authorizedBy === "temporary_grant_overlay" ? "temporary grant" : "authorizer not recorded"}
              </div>
              <div className="rollout">
                <div className="rollout-bar">
                  <span style={{ width: `${latest.devices.length ? (applied / latest.devices.length) * 100 : 0}%` }} />
                </div>
                <span className="small">
                  Endpoint receipts: applied on {applied} of {latest.devices.length}
                </span>
              </div>
            </>
          )}
        </Card>
      </div>

      {attention.length > 0 && (
        <>
          <SectionTitle>Worth a look</SectionTitle>
          <div className="stack">
            {attention.map((i) => (
              <Card key={i.id} as="button" onClick={() => go(`activity/${encodeURIComponent(i.id)}`)} className="notice">
                <div className={`notice-icon tone-${i.kind === "coverage_lost" ? "red" : "amber"}`}>
                  <Icon name={i.kind === "telemetry_gap" ? "clock" : "alert"} size={18} />
                </div>
                <div className="notice-body">
                  <div className="notice-title">{i.kind === "telemetry_gap" ? <>Activity gap on <Ident value={data.devices.find((d) => d.id === i.deviceId)?.name ?? i.deviceId} /></> : <Ident value={i.reason} kind="text" />}</div>
                  <div className="muted small">
                    <Ident value={i.explanation} kind="text" />
                  </div>
                </div>
                <Icon name="chevron" size={16} className="row-chevron" />
              </Card>
            ))}
          </div>
        </>
      )}

      <SectionTitle action={<a href="#/devices" className="link">Devices</a>}>Your devices</SectionTitle>
      <div className="device-strip">
        {data.devices.map((d) => (
          <Card key={d.id} as="button" onClick={() => go(`devices/${d.id}`)} className="device-tile">
            <div className="device-tile-top">
              <span className="device-glyph">
                <DeviceIcon d={d} />
              </span>
              <span className="muted small">{ago(d.lastSeen)}</span>
            </div>
            <div className="device-name">
              <Ident value={d.name} />
            </div>
            <div className="muted small ellipsis">{d.model}</div>
            <CoverageBadge c={fresh(d).coverage} />
          </Card>
        ))}
      </div>

      {data.sessions.some((s) => s.state === "running") && (
        <>
          <SectionTitle action={<a href="#/sessions" className="link">Sessions</a>}>Running protected</SectionTitle>
          <div className="stack">
            {data.sessions
              .filter((s) => s.state === "running")
              .map((s) => (
                <Card key={s.id} as="button" onClick={() => go(`sessions/${s.id}`)} className="session-mini">
                  <div>
                    <div className="session-mini-title">
                      <Chain nodes={s.chain.slice(0, 1)} compact /> <span className="muted">· {s.profile}</span>
                    </div>
                    <div className="muted small">
                      {data.devices.find((d) => d.id === s.deviceId)?.name} · {s.boundary} · started {ago(s.startedAt)}
                    </div>
                  </div>
                  <div className="session-mini-counts">
                    <span className="ok">{s.allowed.reduce((a, b) => a + b.count, 0)}</span>
                    <span className="bad">{s.blocked.reduce((a, b) => a + b.count, 0)}</span>
                  </div>
                </Card>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
