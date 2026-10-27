import { Badge, Card, Chain, CoverageBadge, DeviceIcon, Empty, Icon, Ident, SectionTitle } from "../components/ui";
import { BarStrip, HeatGrid, HexMap, hexFill, Kpi, Ring, SampleTag, Spark } from "../components/charts";
import { useData, useFreshness } from "../data/store";
import { STALE_AFTER_MS } from "../data/freshness";
import { ago, compact } from "../format";
import { DecisionCard } from "./Activity";

function greeting(h = new Date().getHours()) {
  return h < 12 ? "Morning" : h < 18 ? "Afternoon" : "Evening";
}

const NOT_CONFIRMED = ["degraded", "unknown", "recovery-required", "rollback-pending"];

const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 1000) / 10}%` : "–");

/**
 * Overview: the fleet at a glance as a bento grid (one column on a phone). Every figure and chart is computed from
 * the snapshot: hourly flow rollups, consumer-computed device freshness, the latest revision's endpoint receipts and
 * incidents. Nothing is estimated; an empty series shows an empty state, not a placeholder chart.
 */
export function Home({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const decisions = data.incidents.filter((i) => i.state === "open" && i.kind === "blocked_connection" && i.sessionId);
  const attention = data.incidents.filter((i) => i.state === "open" && i.kind !== "blocked_connection" && i.urgency !== "low");
  const devs = data.devices.map((d) => ({ d, f: fresh(d) }));
  const covered = devs.filter((x) => !NOT_CONFIRMED.includes(x.f.coverage)).length;
  const t = data.timeline;
  const blocked = t.reduce((s, p) => s + p.blocked, 0);
  const allowed = t.reduce((s, p) => s + p.allowed, 0);
  const observed = t.reduce((s, p) => s + p.observed, 0);
  const total = blocked + allowed + observed;
  const latest = data.revisions[0];
  const applied = latest ? latest.devices.filter((d) => d.states.some((s) => s.state === "applied" || s.state === "confirmed")).length : 0;
  const running = data.sessions.filter((s) => s.state === "running");
  const verified = running.filter((s) => s.verified).length;

  return (
    <div className="page page-wide">
      <div className="hero">
        <div className="hero-eyebrow">
          {greeting()}
          {data.viewer?.name ? `, ${data.viewer.name}` : ""} · overview
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
      </div>

      <div className="bento bento-stretch bento-kpis">
        <Card className="b-3 kpi-card">
          <Kpi
            label="Covered"
            icon="coverage"
            tone="allowed"
            value={covered}
            unit={`/ ${data.devices.length}`}
            sub={`${data.devices.length - covered} not confirmed`}
            chart={<Ring value={covered} total={data.devices.length} size={52} stroke={6} label={`${covered} of ${data.devices.length} devices with current coverage`} />}
          />
        </Card>
        <Card className="b-3 kpi-card">
          <Kpi label="Blocked" icon="x" tone="blocked" value={compact(blocked)} sub={t.length ? `last ${t.length} h, by policy` : "no flow history yet"} chart={<Spark values={t.map((p) => p.blocked)} label="Blocked attempts per hour" />} />
        </Card>
        <Card className="b-3 kpi-card">
          <Kpi label="Observed" icon="eye" tone="observed" value={compact(observed)} sub="permitted, not enforced" chart={<Spark values={t.map((p) => p.observed)} label="Observed flows per hour" />} />
        </Card>
        <Card className="b-3 kpi-card">
          <Kpi
            label="Protected"
            icon="lock"
            tone="allowed"
            value={verified}
            unit={running.length !== verified ? `/ ${running.length}` : undefined}
            sub={running.length ? `${running.length - verified} self-reported only` : "none running"}
          />
        </Card>
      </div>

      {decisions.length > 0 && (
        <>
          <SectionTitle action={<a href="#/activity" className="link">All activity</a>}>Needs a decision</SectionTitle>
          <div className="bento">
            {decisions.slice(0, 2).map((i) => (
              <div key={i.id} className="b-6">
                <DecisionCard incident={i} go={go} />
              </div>
            ))}
          </div>
        </>
      )}

      <div className="bento">
        <Card className="b-8">
          <div className="card-head">
            <h2>Flows by verdict</h2>
            <SampleTag />
          </div>
          <div className="qual">
            <span>Endpoint rollups</span>
            <span>
              <strong>last {t.length || 24} hours</strong>
            </span>
          </div>
          {t.length ? (
            <>
              <div className="metrics">
                <div className="metric tone-allowed">
                  <span className="metric-label">Allowed</span>
                  <span className="metric-value">
                    {compact(allowed)}
                    <small>{pct(allowed, total)}</small>
                  </span>
                </div>
                <div className="metric tone-observed">
                  <span className="metric-label">Observed</span>
                  <span className="metric-value">
                    {compact(observed)}
                    <small>{pct(observed, total)}</small>
                  </span>
                </div>
                <div className="metric tone-blocked">
                  <span className="metric-label">Blocked</span>
                  <span className="metric-value">
                    {compact(blocked)}
                    <small>{pct(blocked, total)}</small>
                  </span>
                </div>
              </div>
              <BarStrip points={t} />
              <div className="legend-row">
                <span className="tone-allowed">
                  <span className="sw" /> allowed
                </span>
                <span className="tone-observed">
                  <span className="sw" /> observed (permitted, not enforced)
                </span>
                <span className="tone-blocked">
                  <span className="sw" /> blocked by policy
                </span>
              </div>
            </>
          ) : (
            <Empty title="No flow history yet" icon="activity">
              Hourly rollups appear once an endpoint reports flows.
            </Empty>
          )}
        </Card>

        <Card className="b-4">
          <div className="card-head">
            <h2>Blocked, hour by hour</h2>
            <SampleTag />
          </div>
          <div className="qual">
            <span>One cell per hour</span>
            <span>
              <strong>current hour outlined</strong>
            </span>
          </div>
          {t.length ? (
            <>
              <HexMap points={t} />
              <div className="heat-scale" aria-hidden>
                <span>none</span>
                {[0, 0.33, 0.66, 1].map((f) => (
                  <i key={f} style={{ background: hexFill(f) }} />
                ))}
                <span>most</span>
              </div>
            </>
          ) : (
            <Empty title="No hours to show" icon="clock" />
          )}
        </Card>

        <Card className="b-6">
          <div className="card-head">
            <h2>When traffic happens</h2>
            <SampleTag />
          </div>
          <div className="qual">
            <span>Verdict × 4-hour window</span>
            <span>
              <strong>each row scaled to its own peak</strong>
            </span>
          </div>
          {t.length ? <HeatGrid points={t} /> : <Empty title="No flow history yet" icon="activity" />}
        </Card>

        <Card className="b-6" as={latest ? "button" : undefined} onClick={latest ? () => go("rules") : undefined}>
          <div className="card-head">
            <h2>What changed</h2>
            {latest && <Badge tone="blue">rev {latest.revision}</Badge>}
          </div>
          {!latest && <div className="muted small">No policy revision has been signed yet.</div>}
          {latest && (
            <>
              <div className="qual">
                <span>
                  <Ident value={latest.author} />
                </span>
                <span>{ago(latest.createdAt)}</span>
              </div>
              <div className="coverage-top">
                <Ring value={applied} total={latest.devices.length} size={76} stroke={8} label={`Applied on ${applied} of ${latest.devices.length} targeted devices`}>
                  <text x="38" y="43" textAnchor="middle" className="ring-text">
                    {applied}/{latest.devices.length}
                  </text>
                </Ring>
                <div style={{ minWidth: 0 }}>
                  <div className="change-title">
                    <Ident value={latest.title} kind="text" />
                  </div>
                  <div className="muted small">
                    {latest.authorizedBy === "owner_key" ? "Signed with an owner key" : latest.authorizedBy === "narrowing" ? "Narrowing change" : latest.authorizedBy === "temporary_grant_overlay" ? "Temporary grant" : latest.authorizedBy === "delegated_issuer" ? "Delegated approval" : "Authorizer not recorded"}
                  </div>
                  <div className="small" style={{ marginTop: 6 }}>
                    Endpoint receipts: applied on {applied} of {latest.devices.length}
                  </div>
                </div>
              </div>
            </>
          )}
        </Card>

        <Card className="b-6">
          <div className="card-head">
            <h2>Evidence age</h2>
            <a href="#/devices" className="link">
              Devices
            </a>
          </div>
          <div className="qual">
            <span>Last report per device</span>
            <span>
              <strong>older than {STALE_AFTER_MS / 60_000} min shows Unknown</strong>
            </span>
          </div>
          <ul className="age-list">
            {devs.map(({ d, f }) => {
              const frac = f.ageMs === null ? 1 : Math.min(1, f.ageMs / STALE_AFTER_MS);
              return (
                <li key={d.id} className="age-row">
                  <span className="age-name">
                    <Ident value={d.name} />
                  </span>
                  <span className="small muted">
                    {f.stale && (
                      <>
                        <Badge tone="amber">stale</Badge>{" "}
                      </>
                    )}
                    {f.ageMs === null ? "never reported" : ago(d.lastSeen)}
                  </span>
                  <span className={`age-bar ${f.stale ? "tone-amber" : "tone-allowed"}`} role="img" aria-label={f.stale ? "stale" : "current"}>
                    <span style={{ width: `${Math.max(3, frac * 100)}%` }} />
                  </span>
                </li>
              );
            })}
          </ul>
        </Card>

        <div className="b-6 bento-col">
          {attention.length > 0 ? (
            attention.map((i) => (
              <Card key={i.id} as="button" onClick={() => go(`activity/${encodeURIComponent(i.id)}`)} className="notice">
                <div className={`notice-icon tone-${i.kind === "coverage_lost" ? "red" : "amber"}`}>
                  <Icon name={i.kind === "telemetry_gap" ? "clock" : "alert"} size={18} />
                </div>
                <div className="notice-body">
                  <div className="notice-title">
                    {i.kind === "telemetry_gap" ? (
                      <>
                        Activity gap on <Ident value={data.devices.find((d) => d.id === i.deviceId)?.name ?? i.deviceId} />
                      </>
                    ) : (
                      <Ident value={i.reason} kind="text" />
                    )}
                  </div>
                  <div className="muted small">
                    <Ident value={i.explanation} kind="text" />
                  </div>
                </div>
                <Icon name="chevron" size={16} className="row-chevron" />
              </Card>
            ))
          ) : (
            <Card>
              <div className="card-head">
                <h2>Worth a look</h2>
              </div>
              <div className="muted small">No open coverage, telemetry or policy incidents.</div>
            </Card>
          )}
        </div>
      </div>

      <SectionTitle action={<a href="#/devices" className="link">Devices</a>}>Your devices</SectionTitle>
      <div className="device-strip">
        {devs.map(({ d, f }) => (
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
            <CoverageBadge c={f.coverage} />
          </Card>
        ))}
      </div>

      {running.length > 0 && (
        <>
          <SectionTitle action={<a href="#/sessions" className="link">Tasks</a>}>Running protected</SectionTitle>
          <div className="bento">
            {running.map((s) => (
              <Card key={s.id} as="button" onClick={() => go(`sessions/${s.id}`)} className="session-mini b-6">
                <div style={{ minWidth: 0 }}>
                  <div className="session-mini-title">
                    <Chain nodes={s.chain.slice(0, 1)} compact /> <span className="muted">· {s.profile}</span>
                  </div>
                  <div className="muted small">
                    {data.devices.find((d) => d.id === s.deviceId)?.name} · {s.boundary} · started {ago(s.startedAt)}
                  </div>
                </div>
                <div className="session-mini-counts">
                  <span className="ok" aria-label="allowed">
                    <Icon name="check" size={12} /> {s.allowed.reduce((a, b) => a + b.count, 0)}
                  </span>
                  <span className="bad" aria-label="blocked">
                    <Icon name="x" size={12} /> {s.blocked.reduce((a, b) => a + b.count, 0)}
                  </span>
                </div>
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
