/**
 * W12 standalone screens: Apps-first landing, app detail (four sections), "What changed?" and Diagnostics.
 * Live mode reads the controller's evidence views; demo mode says plainly that sample data has no live view.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Badge, Card, Empty, Icon, Ident, SectionTitle, SubNav } from "../components/ui";
import { useData, useFreshness, useStore } from "../data/store";
import type { App, AppDetailView, DiagnosticsView, WhatChangedView } from "../data/types";
import { ago } from "../format";
import { DecisionCard } from "./Activity";

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

/** One compact line: what is enforced, which policy is active, how fresh the evidence is. */
export function StatusLine() {
  const data = useData();
  const fresh = useFreshness();
  const devs = data.devices.map((d) => ({ d, f: fresh(d) }));
  const enforced = devs.filter((x) => x.f.coverage === "enforced" || x.f.coverage === "protected-session").length;
  const gaps = devs.filter((x) => ["degraded", "unknown"].includes(x.f.coverage)).length;
  const newest = data.devices.map((d) => d.lastSeen).filter((x): x is string => !!x).sort().at(-1);
  return (
    <div className="status-line" role="status">
      <span className={`status-dot ${gaps ? "tone-amber" : "tone-green"}`} />
      <span>
        {data.devices.length === 1 ? (enforced ? "Enforcing on this computer" : `This computer: ${devs[0]!.f.coverage}`) : `${enforced}/${data.devices.length} devices enforcing`}
        {gaps > 0 && <strong> · {gaps} not confirmed</strong>}
      </span>
      <span className="muted">· policy rev {data.policyRevision || "none"}</span>
      <span className="muted">· evidence {newest ? ago(newest) : "never reported"}</span>
    </div>
  );
}

function verdictTone(v: string) {
  return v === "deny" ? "red" : v === "observed" ? "neutral" : "green";
}

export function AppCard({ a, go }: { a: App; go: (to: string) => void }) {
  return (
    <Card className="app-card" as="button" onClick={() => go(`apps/${encodeURIComponent(a.id)}`)}>
      <div className="app-top">
        <div className={`app-avatar ${a.identity === "unknown" ? "app-avatar-unknown" : ""}`}>{a.identity === "unknown" ? "?" : a.name.slice(0, 1)}</div>
        <div className="app-meta">
          <div className="app-name">{a.name}</div>
          <div className="muted small ellipsis">
            <Ident value={a.exe} /> · {a.signing}
          </div>
        </div>
        {a.enforcement === "evidence" && a.counts ? (
          <Badge tone={a.counts.denied ? "red" : a.identity === "unknown" ? "amber" : "neutral"}>{a.counts.denied ? `${a.counts.denied} blocked` : a.identity === "unknown" ? "identity unknown" : `${a.counts.flows} seen`}</Badge>
        ) : (
          <Badge tone={a.enforcement === "observed" ? "neutral" : a.enforcement === "session-only" ? "green" : "blue"}>{a.enforcement === "observed" ? "observed" : a.enforcement === "session-only" ? "protected when launched" : "enforced"}</Badge>
        )}
      </div>
      <div className="app-dests">
        {a.destinations.slice(0, 6).map((d) => (
          <span key={d.host + d.verdict} className={`chip chip-${d.verdict}`}>
            <span className="mono">
              <Ident value={d.host} kind="host" />
            </span>
            <span className="chip-count">{d.count}</span>
            {d.firstSeen && <span className="chip-new">new</span>}
          </span>
        ))}
      </div>
      <div className="muted small">
        {a.devices.length} device{a.devices.length === 1 ? "" : "s"} · active {ago(a.lastActive)}
        {a.recognizedBy && ` · recognized by ${a.recognizedBy}`}
      </div>
    </Card>
  );
}

/** Landing: Apps is the primary workspace. Decisions that need the owner come first; a quiet day says so. */
export function AppsHome({ go }: { go: (to: string) => void }) {
  const data = useData();
  const [q, setQ] = useState("");
  const decisions = data.incidents.filter((i) => i.state === "open" && i.kind === "blocked_connection" && i.sessionId);
  const list = data.apps.filter((a) => (a.name + a.family + a.exe + a.category).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="page">
      <StatusLine />
      <div className="page-head">
        <h1>{decisions.length ? `${decisions.length} ${decisions.length === 1 ? "decision" : "decisions"} waiting.` : "All quiet."}</h1>
        <p className="lede">Apps on {data.devices.length === 1 ? "this computer" : "your devices"}, by executable identity. A name alone is never identity; unknown identity stays visible.</p>
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
      <SectionTitle action={<a href="#/changed" className="link">What changed?</a>}>Apps</SectionTitle>
      <label className="search">
        <Icon name="apps" size={16} />
        <input placeholder="Search apps" aria-label="Search apps" value={q} onChange={(e) => setQ(e.target.value)} />
      </label>
      {list.length === 0 ? (
        <Empty title={data.apps.length ? "No app matches" : "No app activity recorded yet"} icon="apps">
          {data.apps.length ? null : "Apps appear here once an endpoint reports a connection. Nothing is shown before there is evidence."}
        </Empty>
      ) : (
        <div className="stack">
          {list.map((a) => (
            <AppCard key={a.id} a={a} go={go} />
          ))}
        </div>
      )}
    </div>
  );
}

const HOW: Record<string, string> = { direct: "names this app", inherited: "applies to every app", session: "inside protected sessions", temporary: "temporary grant" };

function Section({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <Card>
      <SectionTitle action={action}>{title}</SectionTitle>
      {children}
    </Card>
  );
}

export function AppDetail({ id, go }: { id: string; go: (to: string) => void }) {
  const { mode } = useStore();
  const data = useData();
  const live = useLive<AppDetailView>(mode === "live" ? `/v1/apps/${encodeURIComponent(id)}` : null);
  const demo = mode === "demo" ? data.apps.find((a) => a.id === id) : undefined;
  if (mode === "demo") {
    if (!demo) return <Empty title="App not found" icon="apps" />;
    return (
      <div className="page">
        <button type="button" className="back" onClick={() => go("")}>
          <Icon name="chevron" size={14} className="flip" /> Apps
        </button>
        <AppCard a={demo} go={() => undefined} />
        <Card>
          <div className="muted small">Sample data: permissions, recent changes and explanations are computed from a live controller's policy and evidence, so none is shown here.</div>
        </Card>
      </div>
    );
  }
  if (live.loading) return <div className="page muted small" role="status">Loading this app's evidence…</div>;
  if (live.error || !live.data)
    return (
      <div className="page">
        <Empty title="Couldn't load this app" icon="alert">
          {live.error}
        </Empty>
      </div>
    );
  const d = live.data;
  const a = d.app;
  return (
    <div className="page">
      <button type="button" className="back" onClick={() => go("")}>
        <Icon name="chevron" size={14} className="flip" /> Apps
      </button>
      <div className="page-head">
        <h1>{a.name}</h1>
        <p className="lede">
          <Ident value={a.exe ?? "executable not recorded"} mono /> · {a.signer ?? "no signing identity reported"} · seen on {a.devices.join(", ")} · first seen {ago(a.firstSeen)}
        </p>
      </div>
      {d.notes.map((n) => (
        <div key={n} className="note note-amber small">
          {n}
        </div>
      ))}
      <Section title="Current permissions" action={<Badge>rev {d.policy_revision ?? "none"}</Badge>}>
        {d.permissions.length === 0 ? (
          <div className="muted small">{a.identity === "unknown" ? "Rules cannot be matched without an executable identity." : "No rule names this app; its profile default applies (see Why)."}</div>
        ) : (
          <ul className="perm-list">
            {d.permissions.map((p) => (
              <li key={p.rule} className="perm">
                <Badge tone={p.action === "deny" ? "red" : p.action === "observe" ? "neutral" : "green"}>{p.action}</Badge>
                <span className="mono small">{p.rule}</span>
                <span className="muted small">
                  {HOW[p.how]} · {p.layer}
                  {p.expiresAt ? ` · until ${new Date(p.expiresAt).toLocaleString()}` : ""}
                </span>
                {p.devices.filter((x) => !x.enforced).map((x) => (
                  <span key={x.device} className="small tone-text-amber">
                    Not enforced on {x.device}: {x.note}
                  </span>
                ))}
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Recent changes">
        {d.changes.length === 0 && d.identity_variants.length === 0 ? (
          <div className="muted small">No rule naming this app changed in the last ten revisions.</div>
        ) : (
          <ul className="perm-list">
            {d.changes.map((c) => (
              <li key={`${c.revision}-${c.rule}-${c.kind}`} className="perm">
                <Badge tone={c.kind === "removed" ? "neutral" : "blue"}>{c.kind}</Badge>
                <span className="mono small">{c.rule}</span>
                <span className="muted small">
                  rev {c.revision} · {c.by} · {ago(c.at)}
                </span>
              </li>
            ))}
            {d.identity_variants.map((v) => (
              <li key={v.id} className="perm">
                <Badge tone="amber">other identity</Badge>
                <span className="mono small">
                  <Ident value={v.exe} /> {v.signer ? `(${v.signer})` : ""}
                </span>
                <span className="muted small">same family, separate app · first seen {ago(v.firstSeen)} · no permissions are inherited</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Activity" action={<span className="muted small">{a.flows} recorded · {a.denied} blocked</span>}>
        <div className="activity-table">
          {d.activity.slice(0, 20).map((f, i) => (
            <div key={i} className="activity-row small">
              <Badge tone={verdictTone(f.verdict)}>{f.verdict}</Badge>
              <span className="mono ellipsis">
                <Ident value={`${f.destination ?? "unknown"}${f.port ? `:${f.port}` : ""}`} kind="host" />
              </span>
              <span className="muted">
                {f.device}
                {f.session ? ` · session ${f.session}` : ""} · {ago(f.at)}
              </span>
            </div>
          ))}
        </div>
        <div className="footnote">Each row is one endpoint decision record. Counts are records, not bytes or users.</div>
      </Section>
      <Section title="Why the current rules apply">
        {d.why.length === 0 && <div className="muted small">No recorded attempt to explain.</div>}
        {d.why.map((w) => (
          <div key={`${w.destination}:${w.port}`} className="why">
            <div className="mono small">
              <Ident value={`${w.destination}${w.port ? `:${w.port}` : ""}`} kind="host" />
            </div>
            <div className="small">
              <strong>Recorded:</strong> {w.recorded.verdict}
              {w.recorded.rule ? ` by ${w.recorded.rule}` : ""} at rev {w.recorded.revision ?? "?"} ({ago(w.recorded.at)})
            </div>
            <div className="small">
              <strong>Policy now:</strong>{" "}
              {w.now
                ? `${w.now.permitted_by_observation ? "observed (permitted by observation)" : w.now.verdict} · ${w.now.winner?.kind === "profile_default" ? `${w.now.winner.profile} default (${w.now.winner.default})` : (w.now.winner?.rule_id ?? w.now.winner?.id ?? w.now.winner?.kind ?? "")}`
                : `not evaluated: ${w.nowError}`}
            </div>
            {w.now?.notes?.map((n) => (
              <div key={n} className="muted small">
                {n}
              </div>
            ))}
          </div>
        ))}
        <div className="footnote">"Policy now" is the core's deterministic evaluation of the recorded attempt against this device's compiled policy. It is not a prediction of traffic the endpoint has not seen.</div>
      </Section>
    </div>
  );
}

function toLocalInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

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
    <div className="page">
      <SubNav active="changed" />
      <div className="page-head">
        <h1>What changed?</h1>
        <p className="lede">Compare a time it worked with a time it failed. Observed differences come first; possible explanations are labeled as such and each links to a reversible test you review.</p>
      </div>
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
            to
            <input type="datetime-local" value={form.wTo} onChange={set("wTo")} />
          </label>
          <label>
            Failed from
            <input type="datetime-local" value={form.fFrom} onChange={set("fFrom")} />
          </label>
          <label>
            to
            <input type="datetime-local" value={form.fTo} onChange={set("fTo")} />
          </label>
        </div>
        <button type="button" className="btn btn-primary" onClick={run} disabled={mode !== "live"}>
          Compare
        </button>
        {mode !== "live" && <div className="muted small">Comparisons run on a live controller's recorded evidence; sample data has none.</div>}
      </Card>
      {res.loading && <div className="muted small" role="status">Comparing…</div>}
      {res.error && <div className="note note-red small">{res.error}</div>}
      {res.data && (
        <>
          <Section title="Observed differences" action={<span className="muted small">{res.data.counts.working} vs {res.data.counts.failing} records</span>}>
            {res.data.observed.length === 0 ? (
              <div className="muted small">No difference in the recorded evidence between the two intervals.</div>
            ) : (
              res.data.observed.map((o, i) => (
                <div key={i} className="why">
                  <div className="small">
                    <strong>{o.title}</strong>
                  </div>
                  <div className="muted small">
                    Worked: <Ident value={o.working} /> · Failed: <Ident value={o.failing} />
                  </div>
                </div>
              ))
            )}
          </Section>
          <Section title="Possible explanations">
            {res.data.candidates.length === 0 && <div className="muted small">Nothing in the evidence suggests a candidate.</div>}
            {res.data.candidates.map((c, i) => (
              <div key={i} className="why">
                <div className="small">
                  <Badge tone="amber">possible</Badge> <strong>{c.title}</strong>
                </div>
                <div className="muted small">{c.why}</div>
                <button
                  type="button"
                  className="btn btn-quiet small"
                  onClick={() => (c.test.action.startsWith("rollback_preview:") ? go("rules") : c.test.action === "open_diagnostics" ? go("diagnostics") : c.test.action === "open_app" && form.app ? go(`apps/${encodeURIComponent(form.app)}`) : go("activity"))}
                >
                  {c.test.label}
                </button>
              </div>
            ))}
            <div className="footnote">{res.data.disclaimer}</div>
            <div className="footnote">Not compared: {res.data.not_compared.join("; ")}.</div>
          </Section>
        </>
      )}
    </div>
  );
}

export function Diagnostics() {
  const { mode } = useStore();
  const res = useLive<DiagnosticsView>(mode === "live" ? "/v1/diagnostics" : null);
  return (
    <div className="page">
      <SubNav active="diagnostics" />
      <div className="page-head">
        <h1>Diagnostics</h1>
        <p className="lede">Component versions, policy generations, evidence age, capability downgrades and gaps, as recorded. Nothing here is a guess.</p>
      </div>
      {mode !== "live" && (
        <Card>
          <div className="muted small">Diagnostics read a live controller and its devices; sample data has none.</div>
        </Card>
      )}
      {res.loading && <div className="muted small" role="status">Reading diagnostics…</div>}
      {res.error && <div className="note note-red small">{res.error}</div>}
      {res.data && (
        <>
          <Section title="Controller">
            <div className="kv small">
              <span>Version</span>
              <span className="mono">{res.data.controller.version}</span>
              <span>Policy revision</span>
              <span className="mono">{res.data.controller.policy_revision ?? "none"}</span>
              <span>Publications</span>
              <span className="mono">{Object.entries(res.data.controller.publications).map(([k, v]) => `${k} ${v}`).join(" · ") || "none"}</span>
              <span>Flow history</span>
              <span className="mono">{res.data.storage.retention.raw_before ? `raw kept after ${new Date(res.data.storage.retention.raw_before).toLocaleDateString()}` : "retention not run yet"}</span>
            </div>
          </Section>
          {res.data.devices.map((d) => (
            <Section key={d.id} title={d.name} action={<Badge tone={d.health.stale ? "amber" : "green"}>{d.health.stale ? "stale" : d.health.effective_coverage}</Badge>}>
              <div className="kv small">
                <span>Platform</span>
                <span className="mono">
                  {d.platform} {String(d.versions.os ?? "")}
                </span>
                <span>Applied revision</span>
                <span className="mono">{d.policy.applied ?? "none"}</span>
                <span>Latest state</span>
                <span className="mono">{d.policy.latest_state ? `rev ${d.policy.latest_state.revision} ${d.policy.latest_state.state}` : "none"}</span>
                {d.policy.trial && (
                  <>
                    <span>Trial</span>
                    <span className="mono">
                      rev {d.policy.trial.revision}: {d.policy.trial.detail}
                    </span>
                  </>
                )}
                <span>Evidence age</span>
                <span className="mono">{d.health.evidence_age_s === null ? "never reported" : `${Math.round(d.health.evidence_age_s / 60)} min`}</span>
                <span>Acknowledged events</span>
                <span className="mono">
                  up to #{d.spool.acknowledged_seq}
                  {d.spool.gaps.length ? ` · gaps ${d.spool.gaps.map(([a, b]) => `${a}–${b}`).join(", ")}` : ""}
                </span>
              </div>
              {d.health.note && <div className="muted small">{d.health.note}</div>}
              {d.capabilities.downgraded.length > 0 && (
                <div className="small">
                  <strong>Not supported or unproven here:</strong> {d.capabilities.downgraded.map((c) => `${c.key.replace(/_/g, " ")} (${c.support})`).join(", ")}
                </div>
              )}
            </Section>
          ))}
          <Section title="Compatibility tests">
            <div className="muted small">{res.data.compatibility_tests.note}</div>
            {res.data.limits.map((l) => (
              <div key={l} className="muted small">
                {l}
              </div>
            ))}
          </Section>
        </>
      )}
    </div>
  );
}
