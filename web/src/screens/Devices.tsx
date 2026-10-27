import { SubNav, Badge, Card, CoverageBadge, DeviceIcon, Icon, SectionTitle, SupportBadge } from "../components/ui";
import { useData, useFreshness, useStore } from "../data/store";
import { ApprovalsCard } from "./Approvals";
import { ago, compact, COVERAGE } from "../format";
import type { Device } from "../data/types";

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
              {d.sync && d.sync.state !== "current" && <Badge tone={d.sync.state === "pending" || d.sync.state === "not_released" ? "neutral" : "amber"}>{d.sync.state.replace("_", " ")}</Badge>}
              <span className="muted small">{d.dns ? `resolver ${d.dns.resolverHealth.replace(/_/g, " ")} · polled ${ago(d.lastSeen)}` : `${d.revision ? `rev ${d.revision}` : "no policy"} · ${ago(d.lastSeen)}`}</span>
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
          {d.awaitingRetarget && <Badge tone="amber">no snapshot for this device</Badge>}
          {d.sync && d.sync.state !== "current" && (
            <Badge tone={d.sync.state === "pending" || d.sync.state === "not_released" ? "neutral" : "amber"}>
              {d.sync.state.replace("_", " ")}
              {d.sync.desired ? ` · wants rev ${d.sync.desired}` : ""}
            </Badge>
          )}
          <span className="muted small">seen {ago(d.lastSeen)}</span>
        </div>
      </div>
      {d.awaitingRetarget && <RetargetCard />}
      <Card>
        <p className="claim">{COVERAGE[f.coverage].claim}</p>
        <div className="muted small">{f.note ?? d.coverageNote}</div>
      </Card>
      {d.dns ? (
        <DnsEvidence d={d} ageMs={f.ageMs} />
      ) : (
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
      )}
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

/**
 * W16 DNS-only presentation: resolver health and evidence age (the adapter's last good poll), the client's last query
 * and declared history gaps. No flows, processes or bytes: DNS cannot establish them.
 */
function DnsEvidence({ d, ageMs }: { d: Device; ageMs: number | null }) {
  const dns = d.dns!;
  return (
    <>
      <div className="grid-3">
        <Card>
          <div className="stat-label">Resolver</div>
          <div className={`stat-value ${dns.resolverHealth === "ok" ? "" : "bad"}`}>{dns.resolverHealth.replace(/_/g, " ")}</div>
          <div className="muted small">{d.model}</div>
        </Card>
        <Card>
          <div className="stat-label">Evidence age</div>
          <div className="stat-value">{ageMs === null ? "never polled" : ageMs < 60_000 ? "<1 min" : `${Math.round(ageMs / 60_000)} min`}</div>
          <div className="muted small">since the resolver&apos;s last good poll</div>
        </Card>
        <Card>
          <div className="stat-label">Last query</div>
          <div className="stat-value">{ago(dns.lastQueryAt)}</div>
          <div className="muted small">as the resolver reported it</div>
        </Card>
      </div>
      {d.blockedToday > 0 && (
        <div className="grid-3">
          <Card>
            <div className="stat-label">Queries today</div>
            <div className="stat-value">{compact(d.flowsToday)}</div>
          </Card>
          <Card>
            <div className="stat-label">Blocked by the resolver</div>
            <div className="stat-value bad">{compact(d.blockedToday)}</div>
          </Card>
        </div>
      )}
      <Card>
        <SectionTitle>History gaps</SectionTitle>
        {dns.gaps.length === 0 ? (
          <div className="muted small">No dropped resolver history has been detected.</div>
        ) : (
          <ul className="caps">
            {dns.gaps.map((g, i) => (
              <li key={i}>
                <span className="cap-label">{g.from ? ago(g.from) : "?"} – {g.to ? ago(g.to) : "now"}</span>
                <span className="muted small cap-note">{g.reason}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="footnote">DNS evidence says which client asked the resolver for which name, and whether it was blocked. It cannot name an app or process, see a connection or count bytes, and direct-IP or other encrypted-DNS traffic is invisible to it.</div>
      </Card>
    </>
  );
}

/** A device enrolled after the current revision was compiled: its platform's snapshot does not name it. */
function RetargetCard() {
  const { retarget, canAct } = useStore();
  return (
    <Card>
      <p className="claim">The current policy was compiled before this device enrolled, so it has not received it.</p>
      <div className="muted small">
        Each platform&apos;s snapshot is compiled for the devices enrolled at the time and installs only on them. Retarget republishes the same policy (no permission changes) for every enrolled device.
      </div>
      <button type="button" className="btn btn-primary" disabled={!canAct.ok} onClick={() => void retarget()}>Retarget current policy</button>
    </Card>
  );
}
