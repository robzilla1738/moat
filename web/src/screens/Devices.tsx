/**
 * Devices ("Which of my devices are protected, and which need a fix?") and one device ("Is this device protected, and
 * what can Moat do on it?"). DNS-only devices say exactly what a web filter can and cannot see.
 */
import { Actions, Banner, Button, Card, CoverageChip, DeviceIcon, Details, EmptyState, Facts, Fine, Ident, List, ListRow, Page, Stat, StatusChip, SubNav, SupportChip, DEVICE_NAV, type Tone } from "../components/ui";
import { useData, useFreshness, useStore } from "../data/store";
import { ApprovalsCard } from "./Approvals";
import { ago, checked, compact, COVERAGE, NEEDS_ATTENTION, SUPPORT } from "../format";
import type { Device, Support } from "../data/types";
import { deviceSentence } from "./Standalone";

const SYNC: Record<NonNullable<Device["sync"]>["state"], [Tone, string]> = {
  current: ["green", "Up to date"],
  pending: ["neutral", "Update on its way"],
  stale: ["amber", "Behind on rules"],
  rejected: ["red", "Refused an update"],
  held: ["amber", "Update held"],
  not_released: ["neutral", "Not released yet"],
  ahead: ["amber", "Ahead of the controller"],
};

const resolverLabel = (dns: NonNullable<Device["dns"]>) => `via ${dns.resolverKind === "pihole" ? "Pi-hole" : dns.resolverKind === "adguard" ? "AdGuard Home" : "web filter"} (${dns.resolver})`;
const filterHealth = (h: string) => (h === "ok" ? "OK" : h.replace(/_/g, " "));

export function Devices({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const one = data.devices.length === 1;
  return (
    <Page title={one ? "This computer" : "Devices"} lede="Each device protects itself and keeps working when your controller is away." nav={<SubNav items={DEVICE_NAV} active="devices" label="Devices" />}>
      {data.devices.length === 0 ? (
        <EmptyState title="No devices yet" icon="devices">
          Install Moat on a computer, or connect your home web filter, and it appears here.
        </EmptyState>
      ) : (
        <div className="card list-card">
          {data.devices.map((d) => {
            const f = fresh(d);
            return (
              <ListRow
                key={d.id}
                icon={<DeviceIcon d={d} size={18} />}
                title={
                  <>
                    <Ident value={d.name} />
                    {d.isController && <span className="muted"> · runs your controller</span>}
                  </>
                }
                sub={
                  <>
                    <Ident value={deviceSentence(f.note, d.coverageNote, f.coverage)} kind="text" />
                    <br />
                    {d.dns ? `web filter ${filterHealth(d.dns.resolverHealth)} · ${checked(d.lastSeen)}` : checked(d.lastSeen)}
                  </>
                }
                trailing={
                  <span className="chips">
                    <CoverageChip c={f.coverage} />
                    {d.sync && d.sync.state !== "current" && <StatusChip tone={SYNC[d.sync.state][0]}>{SYNC[d.sync.state][1]}</StatusChip>}
                  </span>
                }
                onClick={() => go(`devices/${encodeURIComponent(d.id)}`)}
              />
            );
          })}
        </div>
      )}
      <ApprovalsCard />
    </Page>
  );
}

function supportSummary(caps: { support: Support }[]) {
  const order: Support[] = ["supported", "partial", "untested", "unsupported"];
  return order
    .map((s) => [s, caps.filter((c) => c.support === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${SUPPORT[s].label}: ${n}`)
    .join(" · ");
}

export function DeviceDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const d = data.devices.find((x) => x.id === id);
  void go;
  if (!d)
    return (
      <Page title="Device not found" back={{ label: "Devices", to: "devices" }}>
        <EmptyState title="Device not found" icon="devices" />
      </Page>
    );
  const f = fresh(d);
  const warn = NEEDS_ATTENTION.includes(f.coverage);
  return (
    <Page
      back={{ label: "Devices", to: "devices" }}
      eyebrow={<Ident value={d.model} />}
      title={<Ident value={d.name} />}
    >
      <div className="chips">
        <CoverageChip c={f.coverage} />
        {f.stale && <StatusChip tone="amber">Not current</StatusChip>}
        {d.awaitingRetarget && <StatusChip tone="amber">Doesn&apos;t have your current rules</StatusChip>}
        {d.sync && d.sync.state !== "current" && <StatusChip tone={SYNC[d.sync.state][0]}>{SYNC[d.sync.state][1]}</StatusChip>}
        <span className="muted">{checked(d.lastSeen)}</span>
      </div>
      {warn ? (
        <Banner tone={COVERAGE[f.coverage].tone === "red" ? "red" : "amber"} title={f.coverage === "unknown" ? "We can't confirm this device is protected." : `${COVERAGE[f.coverage].label}.`}>
          <Ident value={deviceSentence(f.note, d.coverageNote, f.coverage)} kind="text" />
        </Banner>
      ) : (
        <Card>
          <p className="claim">{COVERAGE[f.coverage].meaning}</p>
          <p className="muted">
            <Ident value={d.coverageNote} kind="text" />
          </p>
        </Card>
      )}
      {d.awaitingRetarget && <RetargetCard />}
      {d.dns ? (
        <DnsEvidence d={d} ageMs={f.ageMs} />
      ) : (
        <Card title="Today">
          <div className="stats">
            <Stat label="Connections today" value={compact(d.flowsToday)} />
            <Stat label="Blocked today" value={compact(d.blockedToday)} tone={d.blockedToday ? "red" : undefined} />
            <Stat label="Gaps in reports" value={d.telemetryGaps.length} tone={d.telemetryGaps.length ? "amber" : undefined} sub={d.telemetryGaps.length ? "activity in a gap is incomplete" : undefined} />
          </div>
          {d.telemetryGaps.length > 0 && (
            <Details summary="Technical details">
              {d.telemetryGaps.map(([a, b]) => (
                <div key={a} className="mono">
                  events {a}–{b} lost
                </div>
              ))}
            </Details>
          )}
        </Card>
      )}
      {d.capabilities.length > 0 && (
        <Card title="What Moat can do here">
          <p>{supportSummary(d.capabilities)}</p>
          <Details summary={`See all ${d.capabilities.length}`}>
            <List>
              {d.capabilities.map((c) => (
                <ListRow key={c.key} title={c.label} sub={c.note ? <Ident value={c.note} kind="text" /> : undefined} trailing={<SupportChip s={c.support} />} />
              ))}
            </List>
            <Fine>Each device reports what it can do and lowers it when its own checks fail. A rule that needs something a device can&apos;t do is refused, never turned into a weaker one.</Fine>
          </Details>
        </Card>
      )}
      {d.platform === "linux" && (
        <Card title="If something breaks">
          <p>Recovery works at the device even when your controller or network is down. Lockdown never turns itself off.</p>
          <Details summary="Recovery commands">
            <pre className="code">{`sudo moatd recover status
sudo moatd recover disable --reason "..."
sudo moatd recover isolate --keep 100.100.1.2/32`}</pre>
          </Details>
        </Card>
      )}
    </Page>
  );
}

/**
 * W16 DNS-only presentation: the web filter's health and when it last answered (the evidence age), the device's last
 * lookup and declared history gaps. No connections, programs or data counts: DNS cannot establish them.
 */
function DnsEvidence({ d, ageMs }: { d: Device; ageMs: number | null }) {
  const dns = d.dns!;
  return (
    <>
      <Card title="Web filter">
        <div className="stats">
          <Stat label="Web filter" value={filterHealth(dns.resolverHealth)} sub={resolverLabel(dns)} tone={dns.resolverHealth === "ok" ? undefined : "red"} />
          <Stat label="Last checked" value={ageMs === null ? "never" : ageMs < 60_000 ? "<1 min" : ageMs < 3600_000 ? `${Math.round(ageMs / 60_000)} min` : `${Math.round(ageMs / 3600_000)} h`} sub="since the web filter last answered" />
          <Stat label="Last lookup" value={ago(dns.lastQueryAt)} sub="as the web filter reported it" />
        </div>
        {d.blockedToday > 0 && (
          <div className="stats">
            <Stat label="Lookups today" value={compact(d.flowsToday)} />
            <Stat label="Blocked by the web filter" value={compact(d.blockedToday)} tone="red" />
          </div>
        )}
        <Fine>The web filter only sees which device asked for which website, and whether it was blocked. It can&apos;t name an app, see a connection or count data, and it misses direct connections and other encrypted lookups.</Fine>
      </Card>
      <Card title="Gaps in history">
        {dns.gaps.length === 0 ? (
          <p className="muted">No missing web filter history found.</p>
        ) : (
          <List>
            {dns.gaps.map((g, i) => (
              <ListRow key={i} title={`${g.from ? ago(g.from) : "?"} – ${g.to ? ago(g.to) : "now"}`} sub={<Ident value={g.reason} kind="text" />} trailing={<StatusChip tone="amber">Gap</StatusChip>} />
            ))}
          </List>
        )}
      </Card>
    </>
  );
}

/** A device enrolled after the current rules were prepared: its platform's copy does not name it. */
function RetargetCard() {
  const { retarget, canAct } = useStore();
  return (
    <Card title="This device doesn't have your current rules">
      <p>It joined after your current rules were prepared, so it hasn&apos;t received them. Resending changes no permissions.</p>
      <Actions>
        <Button kind="primary" disabled={!canAct.ok} onClick={() => void retarget()}>
          Resend current rules
        </Button>
      </Actions>
      <Details summary="Technical details">
        Each platform&apos;s signed snapshot is compiled for the devices enrolled at the time and installs only on them. Retargeting republishes the same policy for every enrolled device.
      </Details>
    </Card>
  );
}
