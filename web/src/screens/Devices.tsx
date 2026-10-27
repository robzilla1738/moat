import { SubNav, Badge, Card, CoverageBadge, DeviceIcon, Icon, SectionTitle, SupportBadge } from "../components/ui";
import { useData, useFreshness } from "../data/store";
import { ApprovalsCard } from "./Approvals";
import { ago, compact, COVERAGE } from "../format";

export function Devices({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  return (
    <div className="page">
      <SubNav active="devices" />
      <div className="page-head">
        <h1>Devices</h1>
        <p className="lede">Each device enforces locally and keeps working when the controller is away. Phones and the TV are covered through DNS only.</p>
      </div>
      <div className="stack">
        {data.devices.map((d) => (
          <Card key={d.id} as="button" onClick={() => go(`devices/${d.id}`)} className="device-row">
            <span className="device-glyph lg">
              <DeviceIcon d={d} size={20} />
            </span>
            <span className="device-row-main">
              <span className="device-row-top">
                <span className="device-name">{d.name}</span>
                {d.isController && <Badge>controller</Badge>}
              </span>
              <span className="muted small ellipsis">{fresh(d).note ?? d.coverageNote}</span>
            </span>
            <span className="device-row-side">
              <CoverageBadge c={fresh(d).coverage} />
              <span className="muted small">{d.revision ? `rev ${d.revision}` : "no policy"} · {ago(d.lastSeen)}</span>
            </span>
          </Card>
        ))}
      </div>
      <ApprovalsCard />
    </div>
  );
}

export function DeviceDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const d = data.devices.find((x) => x.id === id);
  if (!d) return <div className="page">Not found</div>;
  const f = fresh(d);
  return (
    <div className="page">
      <button type="button" className="back" onClick={() => go("devices")}>
        <Icon name="chevron" size={16} className="flip" /> Devices
      </button>
      <div className="page-head">
        <div className="eyebrow">{d.model}</div>
        <h1 className="detail-title">{d.name}</h1>
        <div className="head-badges">
          <CoverageBadge c={f.coverage} />
          {f.stale && <Badge tone="amber">stale</Badge>}
          {d.revision && <Badge tone="blue">rev {d.revision} {d.revisionState}</Badge>}
          <span className="muted small">seen {ago(d.lastSeen)}</span>
        </div>
      </div>
      <Card>
        <p className="claim">{COVERAGE[f.coverage].claim}</p>
        <div className="muted small">{f.note ?? d.coverageNote}</div>
      </Card>
      <div className="grid-3">
        <Card>
          <div className="stat-label">Flows today</div>
          <div className="stat-value">{compact(d.flowsToday)}</div>
        </Card>
        <Card>
          <div className="stat-label">Blocked today</div>
          <div className="stat-value bad">{compact(d.blockedToday)}</div>
        </Card>
        <Card>
          <div className="stat-label">Telemetry gaps</div>
          <div className="stat-value">{d.telemetryGaps.length}</div>
          {d.telemetryGaps.map(([a, b]) => (
            <div key={a} className="muted small mono">
              events {a}–{b}
            </div>
          ))}
        </Card>
      </div>
      <Card>
        <SectionTitle>Capabilities</SectionTitle>
        <ul className="caps">
          {d.capabilities.map((c) => (
            <li key={c.key}>
              <span className="cap-label">{c.label}</span>
              <span className="muted small cap-note">{c.note}</span>
              <SupportBadge s={c.support} />
            </li>
          ))}
        </ul>
        <div className="footnote">Advertised by the endpoint and downgraded by its own probes. A strict rule that needs an unavailable capability fails validation; it is never compiled into a weaker one.</div>
      </Card>
      {d.platform === "linux" && (
        <Card>
          <SectionTitle>Local recovery</SectionTitle>
          <pre className="code">{`sudo moatd recover status
sudo moatd recover disable --reason "..."
sudo moatd recover isolate --keep 100.100.1.2/32`}</pre>
          <div className="muted small">Works on the device with the controller or Tailscale down. Isolation never reopens on its own.</div>
        </Card>
      )}
    </div>
  );
}
