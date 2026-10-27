/**
 * Overview: "How protected am I?" Three cards, each answering part of that question from the snapshot only:
 *   1. Protection: how many devices are protected, and which ones are not (with why). The ring is the count.
 *   2. Last 24 hours: what was blocked, allowed, or only watched (the one chart: is anything getting through unchecked?).
 *   3. Latest rule change: is it in force on every device it targets?
 * Decisions live on Apps, the full device list on Devices, tasks on Tasks. Nothing here repeats them.
 */
import { Card, CoverageChip, DeviceIcon, EmptyState, Ident, List, ListRow, Page, Stat, StatusChip } from "../components/ui";
import { BarStrip, Ring, SampleTag } from "../components/charts";
import { useData, useFreshness } from "../data/store";
import { ago, checked, compact, NEEDS_ATTENTION, plural, PROTECTED } from "../format";
import { deviceSentence } from "./Standalone";

const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "–");

export function Overview({ go }: { go: (to: string) => void }) {
  const data = useData();
  const fresh = useFreshness();
  const devs = data.devices.map((d) => ({ d, f: fresh(d) }));
  const total = devs.length;
  const prot = devs.filter((x) => PROTECTED.includes(x.f.coverage)).length;
  const notFull = devs.filter((x) => !PROTECTED.includes(x.f.coverage));
  const look = devs.filter((x) => NEEDS_ATTENTION.includes(x.f.coverage)).length;
  const t = data.timeline;
  const blocked = t.reduce((s, p) => s + p.blocked, 0);
  const allowed = t.reduce((s, p) => s + p.allowed, 0);
  const observed = t.reduce((s, p) => s + p.observed, 0);
  const all = blocked + allowed + observed;
  const latest = data.revisions[0];
  const applied = latest ? latest.devices.filter((d) => d.states.some((s) => s.state === "applied" || s.state === "confirmed")).length : 0;

  return (
    <Page wide title={total === 1 ? (prot ? "This computer is protected." : "This computer isn't fully protected.") : `${prot} of ${total} devices protected.`} lede={look ? `${plural(look, "device needs", "devices need")} a look.` : undefined}>
      <div className="bento">
        <Card className="b-7" title="Protection" action={<a href="#/devices" className="link">All devices</a>}>
          <div className="hero-row">
            <Ring value={prot} total={total} size={88} stroke={9} label={`${prot} of ${total} devices protected`}>
              <text x="44" y="50" textAnchor="middle" className="ring-text">
                {prot}/{total}
              </text>
            </Ring>
            <p className="lede">{prot === total ? "Every device is protected and has checked in recently." : "Protected means your rules decide what can connect. Everything else is listed here with the reason."}</p>
          </div>
          {notFull.length > 0 && (
            <List label="Devices that aren't fully protected">
              {notFull.map(({ d, f }) => (
                <ListRow
                  key={d.id}
                  icon={<DeviceIcon d={d} size={16} />}
                  title={<Ident value={d.name} />}
                  sub={
                    <>
                      <Ident value={deviceSentence(f.note, d.coverageNote, f.coverage)} kind="text" /> · {checked(d.lastSeen)}
                    </>
                  }
                  trailing={<CoverageChip c={f.coverage} />}
                  onClick={() => go(`devices/${encodeURIComponent(d.id)}`)}
                />
              ))}
            </List>
          )}
        </Card>

        <Card className="b-5" title="Latest rule change" action={latest ? <a href="#/rules" className="link">Rules</a> : undefined}>
          {!latest ? (
            <EmptyState title="No rules signed yet" icon="rules">
              Once you sign your first rules, this shows whether every device is using them.
            </EmptyState>
          ) : (
            <div className="hero-row">
              <Ring value={applied} total={latest.devices.length} size={72} stroke={8} label={`In force on ${applied} of ${latest.devices.length} devices`}>
                <text x="36" y="41" textAnchor="middle" className="ring-text">
                  {applied}/{latest.devices.length}
                </text>
              </Ring>
              <div className="stack-tight">
                <strong>
                  <Ident value={latest.title} kind="text" />
                </strong>
                <span className="muted">
                  {ago(latest.createdAt)} · in force on {applied} of {plural(latest.devices.length, "device")}
                </span>
                {applied < latest.devices.length && <StatusChip tone="amber">Not on every device yet</StatusChip>}
              </div>
            </div>
          )}
        </Card>

        <Card className="b-12" title="Last 24 hours" action={<SampleTag />}>
          {t.length ? (
            <>
              <div className="stats">
                <Stat label="Blocked" value={compact(blocked)} sub={pct(blocked, all)} tone="red" />
                <Stat label="Allowed by a rule" value={compact(allowed)} sub={pct(allowed, all)} tone="green" />
                <Stat label="Watched only" value={compact(observed)} sub={`${pct(observed, all)} not checked against a rule`} tone="blue" />
              </div>
              <BarStrip points={t} />
              <div className="legend" aria-hidden>
                <span className="tone-green">
                  <i /> allowed
                </span>
                <span className="tone-blue">
                  <i /> watched only
                </span>
                <span className="tone-red">
                  <i /> blocked
                </span>
              </div>
            </>
          ) : (
            <EmptyState title="Nothing recorded yet" icon="activity">
              Connections appear here, hour by hour, once a device reports them.
            </EmptyState>
          )}
        </Card>
      </div>
    </Page>
  );
}
