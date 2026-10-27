/**
 * Coverage & recovery: "What can each device really do, and how do I recover if a change breaks something?"
 * Levels are listed only when a device is at them; the full ability matrix is under a disclosure.
 */
import { Actions, Button, Card, CoverageChip, Details, DeviceIcon, Fine, Ident, List, ListRow, Page, SubNav, SupportChip, DEVICE_NAV } from "../components/ui";
import { useData, useFreshness } from "../data/store";
import type { Coverage } from "../data/types";
import { COVERAGE } from "../format";

const ORDER: Coverage[] = ["recovery-required", "rollback-pending", "isolated", "degraded", "unknown", "protected-session", "enforced", "monitoring", "dns-only"];
const KEYS = ["session_enforcement", "app_enforcement", "process_identity", "ancestor_attribution", "hostname_enforcement", "session_hostname_proxy", "byte_counters", "existing_flow_revocation", "telemetry_completeness"];

export function CoverageScreen({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const computers = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos");
  const levels = ORDER.map((c) => ({ c, devs: data.devices.filter((d) => fresh(d).coverage === c) })).filter((x) => x.devs.length > 0);
  return (
    <Page title="Coverage & recovery" lede="What each device can really do, and how to recover if a change breaks something." nav={<SubNav items={DEVICE_NAV} active="coverage" label="Devices" />}>
      <Card title="Protection levels">
        <List>
          {levels.map(({ c, devs }) => (
            <ListRow
              key={c}
              title={<CoverageChip c={c} />}
              sub={
                <>
                  {COVERAGE[c].meaning}
                  <span className="row-devices">
                    {devs.map((d) => (
                      <button type="button" key={d.id} className="mini-device" onClick={() => go(`devices/${encodeURIComponent(d.id)}`)}>
                        <DeviceIcon d={d} size={14} /> <Ident value={d.name} />
                      </button>
                    ))}
                  </span>
                </>
              }
            />
          ))}
        </List>
        {computers.length > 0 && (
          <Details summary="Compare what each computer can do">
            <div className="matrix-scroll">
              <table className="matrix">
                <thead>
                  <tr>
                    <th />
                    {computers.map((d) => (
                      <th key={d.id}>
                        <Ident value={d.name} />
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {KEYS.map((k) => (
                    <tr key={k}>
                      <th>{computers[0]?.capabilities.find((c) => c.key === k)?.label ?? k}</th>
                      {computers.map((d) => {
                        const c = d.capabilities.find((x) => x.key === k);
                        return <td key={d.id}>{c ? <SupportChip s={c.support} /> : <span className="muted">—</span>}</td>;
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Fine>&ldquo;Not proven yet&rdquo; means built, but not yet shown working on a real device. Nothing here claims Moat blocks everything if it stops.</Fine>
          </Details>
        )}
      </Card>
      <Card title="If a change breaks something">
        <ul className="plain-list">
          <li>A trial change undoes itself unless you keep it on the device.</li>
          <li>You can always go back at the device itself, without your controller: on a Mac, use Recovery in the Moat app (it asks for your password).</li>
          <li>A device that says &ldquo;{COVERAGE["recovery-required"].label}&rdquo; or &ldquo;{COVERAGE["rollback-pending"].label}&rdquo; keeps its last checked rules and waits for you there. Moat doesn&apos;t guess.</li>
        </ul>
        <Details summary="Recovery commands for Linux">
          <pre className="code">{`sudo moatd rollback          # reinstall the previous verified revision
sudo moatd recover status    # what the device enforces now`}</pre>
        </Details>
        <Actions>
          <Button kind="quiet" href="#/diagnostics">
            Open diagnostics
          </Button>
        </Actions>
      </Card>
    </Page>
  );
}
