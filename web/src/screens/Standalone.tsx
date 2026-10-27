/**
 * Apps (the landing view: "Does anything need me right now?"), app detail ("What may this app do, and why?"),
 * "What changed?" ("Something stopped working: what's different?") and Diagnostics (the technical page).
 * Live mode reads the controller's views; sample data says plainly that it has no live view.
 */
import { useEffect, useState } from "react";
import { Actions, Banner, Button, Card, CoverageChip, Details, EmptyState, Facts, Fine, Icon, Ident, List, ListRow, Page, SectionHeader, StatusChip, SubNav, DEVICE_NAV, type Tone } from "../components/ui";
import { useData, useFreshness, useStore } from "../data/store";
import type { App, AppDetailView, DiagnosticsView, Incident, WhatChangedView } from "../data/types";
import { ago, checked, COVERAGE, compact, NEEDS_ATTENTION, plural, PROTECTED, VERDICT } from "../format";
import { AlertTitle, DecisionCard, KIND } from "./Activity";

function useLive<T>(path: string | null): { data: T | null; error: string | null; loading: boolean } {
  const { fetchLive, mode } = useStore();
  const [st, setSt] = useState<{ data: T | null; error: string | null; loading: boolean }>({ data: null, error: null, loading: !!path });
  useEffect(() => {
    if (!path) return;
    let live = true;
    setSt({ data: null, error: null, loading: true });
    fetchLive<T>(path).then(
      (d) => live && setSt({ data: d, error: null, loading: false }),
      (e: Error) => live && setSt({ data: null, error: e.message, loading: false }),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, mode]);
  return st;
}

/**
 * One line on how protected you are, with the newest check time. Devices that need a look are named in a warning
 * banner (never collapsed); otherwise it is a quiet status line that links to Overview.
 */
export function ProtectionLine() {
  const data = useData();
  const fresh = useFreshness();
  const devs = data.devices.map((d) => ({ d, f: fresh(d) }));
  const total = devs.length;
  const prot = devs.filter((x) => PROTECTED.includes(x.f.coverage)).length;
  const look = devs.filter((x) => NEEDS_ATTENTION.includes(x.f.coverage));
  const newest = data.devices.map((d) => d.lastSeen).filter((x): x is string => !!x).sort().at(-1);
  if (look.length)
    return (
      <Banner tone="amber" title={total === 1 ? `This computer: ${COVERAGE[look[0]!.f.coverage].label.toLowerCase()}.` : `${look.length} of your ${total} devices need a look.`} action={<a className="link" href="#/overview">Overview</a>}>
        {total === 1 ? COVERAGE[look[0]!.f.coverage].meaning : look.map((x) => `${x.d.name}: ${COVERAGE[x.f.coverage].label}`).join(" · ")}
      </Banner>
    );
  return (
    <a className="status-line" href="#/overview">
      <span className="tone-green" aria-hidden>
        <Icon name="check" size={16} />
      </span>
      <span>
        {total === 1 ? `This computer: ${COVERAGE[devs[0]!.f.coverage].label}` : `${prot} of ${total} devices protected`}
        <span className="muted"> · {checked(newest)}</span>
      </span>
      <Icon name="chevron" size={14} className="row-chevron" />
    </a>
  );
}

/** What an app is, in one plain line: who signed it, or how Moat recognises it. Raw paths are under Details. */
export function identityLine(a: Pick<App, "identity" | "signing">): string {
  if (a.identity === "unknown" || /identity unknown/i.test(a.signing)) return "Unknown app: no file was reported";
  if (/^(no signing|unsigned)/i.test(a.signing)) return "Not signed: Moat knows it by its file";
  return `Signed by ${a.signing}`;
}

function appChip(a: App): [Tone, string] {
  if (a.enforcement === "evidence" && a.counts) {
    if (a.counts.denied) return ["red", `${compact(a.counts.denied)} blocked`];
    if (a.identity === "unknown") return ["amber", "Unknown app"];
    return ["neutral", plural(a.counts.flows, "connection")];
  }
  if (a.enforcement === "session-only") return ["green", "Protected in tasks"];
  if (a.enforcement === "enforced") return ["green", "Protected"];
  return ["blue", VERDICT.observed.label];
}

export function AppCard({ a, go }: { a: App; go: (to: string) => void }) {
  const [tone, label] = appChip(a);
  const top = [...a.destinations].sort((x, y) => y.count - x.count)[0];
  return (
    <button type="button" className="card card-button app-card" onClick={() => go(`apps/${encodeURIComponent(a.id)}`)}>
      <span className={`app-avatar ${a.identity === "unknown" ? "tone-amber" : ""}`} aria-hidden>
        {a.identity === "unknown" ? "?" : a.name.slice(0, 1)}
      </span>
      <span className="row-main">
        <span className="row-title">
          {a.name} <StatusChip tone={tone}>{label}</StatusChip>
        </span>
        <span className="row-sub">
          <Ident value={identityLine(a)} kind="text" />
        </span>
        <span className="row-sub">
          {top ? (
            <>
              Mostly <Ident value={top.host} kind="host" mono /> ·{" "}
            </>
          ) : null}
          active {ago(a.lastActive)}
        </span>
      </span>
    </button>
  );
}

/** Open alerts that are not decisions: gaps in reports, rollbacks, lost protection. */
function attentionOf(incidents: Incident[]) {
  return incidents.filter((i) => i.state === "open" && i.kind !== "blocked_connection" && i.urgency !== "low");
}

/**
 * Apps, the landing view. Its job: "Does anything need me right now?" Decisions first, then anything else that needs a
 * look, then your apps. No charts and no fleet counters here: those answer Overview's question.
 */
export function AppsHome({ go }: { go: (to: string) => void }) {
  const data = useData();
  const [q, setQ] = useState("");
  const decisions = data.incidents.filter((i) => i.state === "open" && i.kind === "blocked_connection" && i.sessionId);
  const attention = attentionOf(data.incidents);
  const n = decisions.length + attention.length;
  const list = data.apps.filter((a) => (a.name + a.family + a.exe + a.category).toLowerCase().includes(q.toLowerCase()));
  return (
    <Page wide title={n ? `${plural(n, "thing needs", "things need")} you` : "Nothing needs you right now"}>
      <ProtectionLine />
      {decisions.length > 0 && (
        <section className="section">
          <SectionHeader title="Needs your decision" action={decisions.length > 2 ? <a href="#/activity" className="link">All {decisions.length}</a> : undefined} />
          <div className="grid grid-2">
            {decisions.slice(0, 2).map((i) => (
              <DecisionCard key={i.id} incident={i} go={go} />
            ))}
          </div>
        </section>
      )}
      {attention.length > 0 && (
        <section className="section">
          <SectionHeader title="Needs a look" />
          <div className="card list-card">
            {attention.map((i) => (
              <ListRow
                key={i.id}
                icon={<Icon name={KIND[i.kind].icon} size={16} />}
                iconTone={KIND[i.kind].tone}
                title={<AlertTitle i={i} deviceName={data.devices.find((d) => d.id === i.deviceId)?.name ?? i.deviceId} />}
                sub={<Ident value={i.explanation} kind="text" />}
                onClick={() => go(`activity/${encodeURIComponent(i.id)}`)}
              />
            ))}
          </div>
        </section>
      )}
      {n === 0 && (
        <EmptyState title="All clear" icon="check" action={<Button kind="quiet" href="#/activity">See activity</Button>}>
          Moat checks the connections your apps make. Anything that needs a decision shows up here first.
        </EmptyState>
      )}
      <section className="section">
        <SectionHeader title="Apps" action={<a href="#/changed" className="link">Something stopped working?</a>} />
        {data.apps.length > 6 && (
          <label className="search">
            <Icon name="apps" size={16} />
            <input placeholder="Search apps" aria-label="Search apps" value={q} onChange={(e) => setQ(e.target.value)} />
          </label>
        )}
        {list.length === 0 ? (
          <EmptyState title={data.apps.length ? "No app matches" : "No apps yet"} icon="apps">
            {data.apps.length ? null : "Apps appear here once a device reports a connection. Nothing is listed before then."}
          </EmptyState>
        ) : (
          <div className="grid grid-apps">
            {list.map((a) => (
              <AppCard key={a.id} a={a} go={go} />
            ))}
          </div>
        )}
      </section>
    </Page>
  );
}

const HOW: Record<string, string> = { direct: "names this app", inherited: "applies to every app", session: "inside protected tasks", temporary: "temporary permission" };
const verdictTone = (v: string): Tone => (v === "deny" ? "red" : v === "observed" ? "blue" : "green");
const verdictLabel = (v: string) => (v === "deny" ? VERDICT.blocked.label : v === "observed" ? VERDICT.observed.label : VERDICT.allowed.label);
const actionLabel = (a: string) => (a === "deny" ? "Blocks" : a === "observe" ? "Watches" : "Allows");

/** App detail: "What may this app do, and why?" Three cards; file paths, signer and rule versions under Details. */
export function AppDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { mode } = useStore();
  const data = useData();
  const live = useLive<AppDetailView>(mode === "live" ? `/v1/apps/${encodeURIComponent(id)}` : null);
  const demo = mode === "demo" ? data.apps.find((a) => a.id === id) : undefined;
  void go;
  if (mode === "demo") {
    if (!demo) return <Page title="App not found" back={{ label: "Apps", to: "" }}><EmptyState title="App not found" icon="apps" /></Page>;
    return (
      <Page title={demo.name} lede={identityLine(demo)} back={{ label: "Apps", to: "" }}>
        <Banner tone="blue" title="Sample data has no rules for this app.">
          With a live controller, this page shows what the app may do, recent changes, and why each connection was allowed or blocked.
        </Banner>
        <Card title="Where it connects">
          <List>
            {demo.destinations.map((d) => (
              <ListRow key={d.host} title={<Ident value={d.host} kind="host" mono />} sub={plural(d.count, "connection")} trailing={<StatusChip tone={verdictTone(d.verdict)}>{verdictLabel(d.verdict)}</StatusChip>} />
            ))}
          </List>
          <Details summary="Technical details">
            <Facts rows={[["File", <Ident key="e" value={demo.exe} mono />], ["Signature", demo.signing], ["Devices", demo.devices.join(", ")]]} />
          </Details>
        </Card>
      </Page>
    );
  }
  if (live.loading) return <div className="page muted" role="status">Loading this app…</div>;
  if (live.error || !live.data)
    return (
      <Page title="Couldn't load this app" back={{ label: "Apps", to: "" }}>
        <EmptyState title="Couldn't load this app" icon="alert">
          {live.error}
        </EmptyState>
      </Page>
    );
  const d = live.data;
  const a = d.app;
  const app: Pick<App, "identity" | "signing"> = { identity: a.identity, signing: a.signer ?? (a.identity === "unknown" ? "identity unknown" : "no signing identity reported") };
  return (
    <Page title={a.name} lede={`${identityLine(app)} · seen on ${a.devices.join(", ")}`} back={{ label: "Apps", to: "" }}>
      {d.notes.map((n) => (
        <Banner key={n} tone="amber" title="Check this app's identity.">
          <Ident value={n} kind="text" />
        </Banner>
      ))}
      <Card title="What it's allowed to do">
        {d.permissions.length === 0 ? (
          <p className="muted">{a.identity === "unknown" ? "Rules can't match an app Moat can't identify." : "No rule names this app, so the default for its device applies (see below)."}</p>
        ) : (
          <List>
            {d.permissions.map((p) => (
              <div key={p.rule} className="row">
                <span className="row-main">
                  <span className="row-title">
                    <StatusChip tone={verdictTone(p.action === "observe" ? "observed" : p.action)}>{actionLabel(p.action)}</StatusChip> <Ident value={p.rule} mono />
                  </span>
                  <span className="row-sub">
                    {HOW[p.how]}
                    {p.expiresAt ? ` · until ${new Date(p.expiresAt).toLocaleString()}` : ""}
                  </span>
                  {p.devices
                    .filter((x) => !x.enforced)
                    .map((x) => (
                      <span key={x.device} className="row-sub tone-amber">
                        <Icon name="alert" size={12} /> Doesn&apos;t apply on <Ident value={x.device} />: <Ident value={x.note} kind="text" />
                      </span>
                    ))}
                </span>
              </div>
            ))}
          </List>
        )}
        <SectionHeader title="Recent changes" level={3} />
        {d.changes.length === 0 && d.identity_variants.length === 0 ? (
          <p className="muted">No rule for this app changed recently.</p>
        ) : (
          <List>
            {d.changes.map((c) => (
              <ListRow key={`${c.revision}-${c.rule}-${c.kind}`} title={<Ident value={c.rule} mono />} sub={`${c.kind} by ${c.by} · ${ago(c.at)} · version ${c.revision}`} />
            ))}
            {d.identity_variants.map((v) => (
              <ListRow key={v.id} title={<StatusChip tone="amber">Another version of this app</StatusChip>} sub={`A different file or signer first seen ${ago(v.firstSeen)}. It is treated as a separate app; no permissions carry over.`} />
            ))}
          </List>
        )}
        <Details summary="Technical details">
          <Facts
            rows={[
              ["File", <Ident key="e" value={a.exe ?? "executable not recorded"} mono />],
              ["Signature", a.signer ?? "no signing identity reported"],
              ["Rule version", String(d.policy_revision ?? "none")],
              ["First seen", ago(a.firstSeen)],
              ...d.identity_variants.map((v) => ["Other version", <Ident key={v.id} value={`${v.exe ?? "?"} ${v.signer ? `(${v.signer})` : ""}`} mono />] as [string, JSX.Element]),
            ]}
          />
        </Details>
      </Card>
      <Card title="Recent activity" action={<span className="muted">{plural(a.flows, "connection")} · {a.denied} blocked</span>}>
        <List>
          {d.activity.slice(0, 8).map((f, i) => (
            <ListRow
              key={i}
              title={<Ident value={`${f.destination ?? "unknown"}${f.port ? `:${f.port}` : ""}`} kind="host" mono />}
              sub={`${f.device}${f.session ? " · in a task" : ""} · ${ago(f.at)}`}
              trailing={<StatusChip tone={verdictTone(f.verdict)}>{verdictLabel(f.verdict)}</StatusChip>}
            />
          ))}
        </List>
        <Fine>Each line is one connection a device recorded. Counts are connections, not data.</Fine>
      </Card>
      <Card title="Why it was allowed or blocked">
        {d.why.length === 0 && <p className="muted">Nothing to explain yet.</p>}
        {d.why.map((w) => (
          <div key={`${w.destination}:${w.port}`} className="why">
            <Ident value={`${w.destination}${w.port ? `:${w.port}` : ""}`} kind="host" mono />
            <span>
              <strong>Recorded:</strong> {verdictLabel(w.recorded.verdict)} {ago(w.recorded.at)}
            </span>
            <span>
              <strong>Rules now:</strong> {w.now ? (w.now.permitted_by_observation ? VERDICT.observed.label : verdictLabel(w.now.verdict ?? "")) : "can't tell"}
            </span>
            <Details summary="Technical details">
              <Facts
                rows={[
                  ["Recorded", `${w.recorded.verdict}${w.recorded.rule ? ` by ${w.recorded.rule}` : ""} at version ${w.recorded.revision ?? "?"}`],
                  ["Now", w.now ? `${w.now.permitted_by_observation ? "observed (permitted by observation)" : w.now.verdict} · ${w.now.winner?.kind === "profile_default" ? `${w.now.winner.profile} default (${w.now.winner.default})` : (w.now.winner?.rule_id ?? w.now.winner?.id ?? w.now.winner?.kind ?? "")}` : `not evaluated: ${w.nowError}`],
                  ...(w.now?.notes ?? []).map((n) => ["Note", n] as [string, string]),
                ]}
              />
            </Details>
          </div>
        ))}
        <Fine>&ldquo;Rules now&rdquo; checks the recorded connection against this device&apos;s current rules. It doesn&apos;t predict connections the device hasn&apos;t seen.</Fine>
      </Card>
    </Page>
  );
}

function toLocalInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** "Something stopped working: what's different?" Compare a time it worked with a time it failed. */
export function WhatChanged({ go }: { go: (to: string) => void }) {
  const { mode } = useStore();
  const data = useData();
  const now = Date.now();
  const [form, setForm] = useState({ device: data.devices.length === 1 ? data.devices[0]!.id : "", app: "", wFrom: toLocalInput(new Date(now - 26 * 3600_000)), wTo: toLocalInput(new Date(now - 24 * 3600_000)), fFrom: toLocalInput(new Date(now - 3600_000)), fTo: toLocalInput(new Date(now)) });
  const [path, setPath] = useState<string | null>(null);
  const res = useLive<WhatChangedView>(path);
  const iso = (s: string) => new Date(s).toISOString();
  const run = () => {
    const q = new URLSearchParams({ working: `${iso(form.wFrom)}/${iso(form.wTo)}`, failing: `${iso(form.fFrom)}/${iso(form.fTo)}` });
    if (form.device) q.set("device", form.device);
    if (form.app) q.set("app", form.app);
    setPath(`/v1/what-changed?${q}`);
  };
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  return (
    <Page title="What changed?" lede="Something stopped working? Compare a time it worked with a time it didn't. Moat lists real differences first, then possible causes you can test." nav={<SubNav items={DEVICE_NAV} active="changed" label="Devices" />}>
      <Card>
        <div className="form-grid">
          <label>
            Device
            <select value={form.device} onChange={set("device")}>
              <option value="">All devices</option>
              {data.devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            App
            <select value={form.app} onChange={set("app")}>
              <option value="">All apps</option>
              {data.apps.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Worked from
            <input type="datetime-local" value={form.wFrom} onChange={set("wFrom")} />
          </label>
          <label>
            until
            <input type="datetime-local" value={form.wTo} onChange={set("wTo")} />
          </label>
          <label>
            Failed from
            <input type="datetime-local" value={form.fFrom} onChange={set("fFrom")} />
          </label>
          <label>
            until
            <input type="datetime-local" value={form.fTo} onChange={set("fTo")} />
          </label>
        </div>
        <Actions>
          <Button kind="primary" onClick={run} disabled={mode !== "live"}>
            Compare
          </Button>
        </Actions>
        {mode !== "live" && <Fine>Comparing needs a live controller&apos;s records; sample data has none.</Fine>}
      </Card>
      {res.loading && (
        <div className="muted" role="status">
          Comparing…
        </div>
      )}
      {res.error && <p className="error">{res.error}</p>}
      {res.data && (
        <>
          <Card title="What's different" action={<span className="muted">{res.data.counts.working} vs {res.data.counts.failing} connections</span>}>
            {res.data.observed.length === 0 ? (
              <p className="muted">Nothing differs in what Moat recorded for these two times.</p>
            ) : (
              <List>
                {res.data.observed.map((o, i) => (
                  <ListRow key={i} title={<Ident value={o.title} kind="text" />} sub={<>Worked: <Ident value={o.working} /> · Failed: <Ident value={o.failing} /></>} />
                ))}
              </List>
            )}
          </Card>
          <Card title="Possible causes">
            {res.data.candidates.length === 0 && <p className="muted">Nothing in the records points to a cause.</p>}
            {res.data.candidates.map((c, i) => (
              <div key={i} className="why">
                <span>
                  <StatusChip tone="amber">Possible</StatusChip> <strong><Ident value={c.title} kind="text" /></strong>
                </span>
                <span className="muted">
                  <Ident value={c.why} kind="text" />
                </span>
                <Actions>
                  <Button kind="quiet" onClick={() => (c.test.action.startsWith("rollback_preview:") ? go("rules") : c.test.action === "open_diagnostics" ? go("diagnostics") : c.test.action === "open_app" && form.app ? go(`apps/${encodeURIComponent(form.app)}`) : go("activity"))}>
                    {c.test.label}
                  </Button>
                </Actions>
              </div>
            ))}
            <Fine>
              <Ident value={res.data.disclaimer} kind="text" />
            </Fine>
            <Details summary="Not compared">
              <Ident value={res.data.not_compared.join("; ")} kind="text" />
            </Details>
          </Card>
        </>
      )}
    </Page>
  );
}

/** Diagnostics: the technical page. It says exactly what each part reports, in the parts' own terms. */
export function Diagnostics() {
  const { mode } = useStore();
  const res = useLive<DiagnosticsView>(mode === "live" ? "/v1/diagnostics" : null);
  return (
    <Page title="Diagnostics" lede="Exactly what each part of Moat reports, for troubleshooting. Nothing here is a guess." back={{ label: "Coverage & recovery", to: "coverage" }}>
      {mode !== "live" && <Banner tone="blue" title="Sample data has no diagnostics.">Diagnostics read a live controller and its devices.</Banner>}
      {res.loading && (
        <div className="muted" role="status">
          Reading diagnostics…
        </div>
      )}
      {res.error && <p className="error">{res.error}</p>}
      {res.data && (
        <div data-tech="">
          <Card title="Controller">
            <Facts
              rows={[
                ["Version", <span key="v" className="mono">{res.data.controller.version}</span>],
                ["Policy revision", <span key="p" className="mono">{res.data.controller.policy_revision ?? "none"}</span>],
                ["Publications", <span key="u" className="mono">{Object.entries(res.data.controller.publications).map(([k, v]) => `${k} ${v}`).join(" · ") || "none"}</span>],
                ["Flow history", <span key="f" className="mono">{res.data.storage.retention.raw_before ? `raw kept after ${new Date(res.data.storage.retention.raw_before).toLocaleDateString()}` : "retention not run yet"}</span>],
              ]}
            />
          </Card>
          {res.data.devices.map((d) => (
            <Card key={d.id} title={d.name} action={d.health.stale ? <StatusChip tone="amber">Not current</StatusChip> : <StatusChip tone="green">{d.health.effective_coverage}</StatusChip>}>
              <Facts
                rows={[
                  ["Platform", <span key="p" className="mono">{d.platform} {String(d.versions.os ?? "")}</span>],
                  ["Applied revision", <span key="a" className="mono">{d.policy.applied ?? "none"}</span>],
                  ["Latest state", <span key="l" className="mono">{d.policy.latest_state ? `rev ${d.policy.latest_state.revision} ${d.policy.latest_state.state}` : "none"}</span>],
                  ...(d.policy.trial ? ([["Trial", <span key="t" className="mono">rev {d.policy.trial.revision}: {d.policy.trial.detail}</span>]] as [string, JSX.Element][]) : []),
                  ["Evidence age", <span key="e" className="mono">{d.health.evidence_age_s === null ? "never reported" : `${Math.round(d.health.evidence_age_s / 60)} min`}</span>],
                  ["Acknowledged events", <span key="k" className="mono">up to #{d.spool.acknowledged_seq}{d.spool.gaps.length ? ` · gaps ${d.spool.gaps.map(([x, y]) => `${x}–${y}`).join(", ")}` : ""}</span>],
                ]}
              />
              {d.health.note && <p className="muted">{d.health.note}</p>}
              {d.capabilities.downgraded.length > 0 && (
                <p>
                  <strong>Not supported or unproven here:</strong> {d.capabilities.downgraded.map((c) => `${c.key.replace(/_/g, " ")} (${c.support})`).join(", ")}
                </p>
              )}
            </Card>
          ))}
          <Card title="Compatibility tests">
            <p className="muted">{res.data.compatibility_tests.note}</p>
            {res.data.limits.map((l) => (
              <p key={l} className="muted">
                {l}
              </p>
            ))}
          </Card>
        </div>
      )}
    </Page>
  );
}

/** A device's single plain status sentence: the freshness note when there is one, else what its level means. */
export function deviceSentence(note: string | null, coverageNote: string, c: keyof typeof COVERAGE) {
  return note ?? (c === "unknown" ? COVERAGE.unknown.meaning : coverageNote || COVERAGE[c].meaning);
}

export { CoverageChip };
