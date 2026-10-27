import { SubNav, Badge, Card, CoverageBadge, DeviceIcon, SectionTitle, SupportBadge } from "../components/ui";
import { useData, useFreshness } from "../data/store";
import type { Coverage } from "../data/types";
import { COVERAGE } from "../format";

const ORDER: Coverage[] = ["protected-session", "enforced", "monitoring", "dns-only", "degraded", "isolated", "unknown"];
const KEYS = ["session_enforcement", "app_enforcement", "process_identity", "ancestor_attribution", "hostname_enforcement", "session_hostname_proxy", "byte_counters", "existing_flow_revocation", "telemetry_completeness"];

export function CoverageScreen({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const endpoints = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos");
  return (
    <div className="page">
      <SubNav active="coverage" />
      <div className="page-head">
        <h1>Coverage & recovery</h1>
        <p className="lede">What each device can actually establish. Weaker coverage is labeled, never presented as equivalent protection.</p>
      </div>
      <Card className="recovery-card">
        <SectionTitle>Local recovery</SectionTitle>
        <div className="small">If a change breaks something, recovery happens on the device itself and never needs this controller:</div>
        <ul className="small">
          <li>A trial revision reverts on its own unless you confirm it on the device.</li>
          <li>On Linux, <span className="mono">sudo moatd rollback</span> reinstalls the previous verified revision; on the Mac, use Recovery in the Moat app (owner authentication required).</li>
          <li>A device that reports <span className="mono">recovery-required</span> or <span className="mono">rollback-pending</span> needs you at the device: Moat keeps the last verified policy in force and does not guess.</li>
        </ul>
        <div className="decision-actions">
          <a className="btn btn-quiet" href="#/diagnostics">Diagnostics</a>
          <a className="btn btn-quiet" href="#/changed">What changed?</a>
        </div>
      </Card>
      <div className="levels">
        {ORDER.map((c) => {
          const n = data.devices.filter((d) => fresh(d).coverage === c);
          return (
            <Card key={c} className={`level ${n.length ? "" : "level-empty"}`}>
              <div className="level-top">
                <CoverageBadge c={c} />
                <span className="level-count">{n.length}</span>
              </div>
              <div className="small">{COVERAGE[c].claim}</div>
              <div className="level-devices">
                {n.map((d) => (
                  <button type="button" key={d.id} className="mini-device" onClick={() => go(`devices/${d.id}`)}>
                    <DeviceIcon d={d} size={14} /> {d.name}
                  </button>
                ))}
              </div>
            </Card>
          );
        })}
      </div>
      <Card className="matrix-card">
        <SectionTitle action={<Badge>endpoints</Badge>}>Capability matrix</SectionTitle>
        <div className="matrix-scroll">
          <table className="matrix">
            <thead>
              <tr>
                <th />
                {endpoints.map((d) => (
                  <th key={d.id}>{d.name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {KEYS.map((k) => (
                <tr key={k}>
                  <th>{endpoints[0]?.capabilities.find((c) => c.key === k)?.label ?? k}</th>
                  {endpoints.map((d) => {
                    const c = d.capabilities.find((x) => x.key === k);
                    return <td key={d.id}>{c ? <SupportBadge s={c.support} /> : <span className="muted">—</span>}</td>;
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="footnote">“Needs device proof” means implemented but not yet demonstrated on a real device in the declared matrix. Nothing here claims fail-closed behavior.</div>
      </Card>
    </div>
  );
}
