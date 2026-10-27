/**
 * W14 review screens (MASTER_ROADMAP §9.4, §9.7): learning capture, candidate review with the permission diff and its
 * evidence, baseline accept (owner sign-in) and enforce (owner key), the drift queue, and the pack browser with each
 * pack's effective delta and unsupported cells. Learning produces a proposal, never trust.
 */
import { useEffect, useState } from "react";
import { Badge, Card, Empty, Icon, Ident, SectionTitle } from "../components/ui";
import { useData, useStore } from "../data/store";
import type { WireProposal } from "../data/api";
import { acceptBody, demoLearning, demoPacks, gapKind, SUPPORT_TONE, type Baseline, type Candidate, type LearningOverview, type PackDelta, type PackSummary } from "../data/learning";
import { ago } from "../format";
import { ProposalPanel } from "./Rules";

type Load<T> = { data: T | null; error: string | null; reload: () => void };

/** Live views come from the controller; demo mode shows the fixed sample and says so. */
function useView<T>(path: string, demo: T | null): Load<T> {
  const { fetchLive, mode } = useStore();
  const [n, setN] = useState(0);
  const [st, setSt] = useState<{ data: T | null; error: string | null }>({ data: mode === "demo" ? demo : null, error: null });
  useEffect(() => {
    if (mode === "demo") {
      setSt({ data: demo, error: demo ? null : "Not in the sample data." });
      return;
    }
    let live = true;
    fetchLive<T>(path).then(
      (d) => live && setSt({ data: d, error: null }),
      (e: Error) => live && setSt({ data: null, error: e.message }),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, mode, n]);
  return { ...st, reload: () => setN((x) => x + 1) };
}

export function LearningNav({ active }: { active: "rules" | "learning" | "packs" }) {
  return (
    <nav className="subnav learn-nav" aria-label="Rules, learning and packs">
      <a href="#/rules" className={active === "rules" ? "active" : ""}>
        Rules
      </a>
      <a href="#/learning" className={active === "learning" ? "active" : ""}>
        Learning
      </a>
      <a href="#/learning/packs" className={active === "packs" ? "active" : ""}>
        Packs
      </a>
    </nav>
  );
}

function Gaps({ reasons }: { reasons: string[] }) {
  if (!reasons.length) return <div className="small ok">No gaps: no lost events, no pending holes, every connection attributed.</div>;
  return (
    <ul className="gap-list" aria-label="Why the evidence is incomplete">
      {reasons.map((r) => (
        <li key={r}>
          <Badge tone={gapKind(r) === "identity" ? "red" : "amber"}>{gapKind(r) === "identity" ? "unknown identity" : gapKind(r) === "lost" ? "lost events" : gapKind(r) === "pending" ? "not all arrived" : gapKind(r) === "import" ? "not observed here" : "gap"}</Badge>
          <span className="small">{r}</span>
        </li>
      ))}
    </ul>
  );
}

const exeName = (exe: string) => exe.split("/").pop() || exe;
const KIND: Record<Candidate["kind"], string> = { capture: "from a capture", drift: "drift since approval", import: "imported" };

function CandidateRow({ c, go }: { c: Candidate; go: (to: string) => void }) {
  return (
    <button type="button" className="learn-row learn-row-button" onClick={() => go(`learning/c/${encodeURIComponent(c.id)}`)}>
      <div className="learn-row-main">
        <div className="learn-row-head">
          <span className="learn-row-title">
            <Ident value={exeName(c.exe)} />
          </span>
          <Badge tone={c.completeness === "complete" ? "green" : "amber"}>{c.completeness}</Badge>
        </div>
        <div className="small muted">
          <span className="mono">
            <Ident value={c.exe} />
          </span>{" "}
          · {c.device_id} · {KIND[c.kind]} · {ago(c.created_at)}
        </div>
        <div className="small">
          {c.permission_diff.adds} would broaden · {c.entries.length} proposed{c.identity_changes.length > 0 && ` · ${c.identity_changes.length} identity change`}
          {c.removal_proposals.length > 0 && ` · ${c.removal_proposals.length} unused`}
        </div>
      </div>
      <Icon name="chevron" size={16} className="row-chevron" />
    </button>
  );
}

/** Start a bounded capture: one device, one exact executable, one named workflow and network context, a time box. */
function CaptureControl({ onStarted, limits }: { onStarted: () => void; limits: LearningOverview["limits"] }) {
  const data = useData();
  const { postLive, mode, canAct, say } = useStore();
  const enforcing = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos");
  const [f, setF] = useState({ device_id: enforcing[0]?.id ?? "", exe: "", workflow: "", network_context: "", hours: "1" });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const start = async () => {
    setErr(null);
    if (!f.exe.startsWith("/")) return setErr("Name one exact executable path. A name alone is never identity.");
    if (!f.workflow.trim() || !f.network_context.trim()) return setErr("Name the workflow and the network context: a normal session and a dependency install are different captures.");
    const hours = Number(f.hours);
    if (!(hours > 0 && hours <= limits.max_capture_hours)) return setErr(`A capture lasts at most ${limits.max_capture_hours} hours.`);
    if (mode === "demo") return say("Demo: no capture was started. In live mode the controller records one bounded window; existing rules stay enforced.");
    try {
      const r = await postLive<{ id: string; note: string }>("/v1/learning/captures", { ...f, hours });
      say(r.note);
      onStarted();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Card className="learn-capture">
      <SectionTitle action={<Badge tone="blue">bounded</Badge>}>Capture a workflow</SectionTitle>
      <div className="small muted">Records what one app does during one workflow so you can review it. Existing rules, including every deny, stay enforced while it runs. Nothing seen is trusted until you review it.</div>
      <div className="form-grid">
        <label>
          Device
          <select value={f.device_id} onChange={set("device_id")}>
            {enforcing.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Executable (exact path)
          <input className="mono" value={f.exe} onChange={set("exe")} placeholder="/usr/bin/npm" spellCheck={false} />
        </label>
        <label>
          Workflow
          <input value={f.workflow} onChange={set("workflow")} placeholder="npm install" />
        </label>
        <label>
          Network context
          <input value={f.network_context} onChange={set("network_context")} placeholder="home LAN" />
        </label>
        <label>
          Hours (at most {limits.max_capture_hours})
          <input type="number" min={1} max={limits.max_capture_hours} value={f.hours} onChange={set("hours")} />
        </label>
      </div>
      {err && <div className="small bad">{err}</div>}
      <div className="decision-actions">
        <button type="button" className="btn btn-primary" onClick={start} disabled={mode === "live" && !canAct.ok}>
          Start capture
        </button>
      </div>
      {mode === "live" && canAct.reason && <div className="small muted">{canAct.reason}</div>}
    </Card>
  );
}

export function Learning({ go }: { go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const v = useView<LearningOverview>("/v1/learning", demoLearning);
  const close = async (id: string) => {
    if (mode === "demo") return say("Demo: nothing was sent. Closing a capture turns its window into a candidate for review.");
    try {
      const c = await postLive<Candidate>(`/v1/learning/captures/${encodeURIComponent(id)}/close`, {});
      go(`learning/c/${encodeURIComponent(c.id)}`);
    } catch (e) {
      say((e as Error).message);
    }
  };
  return (
    <div className="page">
      <LearningNav active="learning" />
      <div className="page-head">
        <h1>Learning</h1>
        <p className="lede">Learning produces a proposal, never trust. Capture one workflow, review every destination it used, then enforce what you accepted with your owner key.</p>
      </div>
      {v.error && !v.data && (
        <Card>
          <div className="small bad">Could not load learning: {v.error}</div>
        </Card>
      )}
      {v.data && (
        <>
          <CaptureControl onStarted={v.reload} limits={v.data.limits} />
          <Card>
            <SectionTitle action={<span className="muted small">{v.data.captures.filter((c) => c.state !== "closed").length} open</span>}>Captures</SectionTitle>
            {v.data.captures.length === 0 && <div className="small muted">No capture yet.</div>}
            {v.data.captures.map((c) => (
              <div key={c.id} className="learn-row">
                <div className="learn-row-main">
                  <div className="learn-row-head">
                    <span className="learn-row-title">{c.workflow}</span>
                    <Badge tone={c.state === "capturing" ? "blue" : c.state === "window_ended" ? "amber" : "neutral"} dot={c.state === "capturing"}>
                      {c.state === "capturing" ? "capturing" : c.state === "window_ended" ? "window ended" : "closed"}
                    </Badge>
                  </div>
                  <div className="small muted">
                    <span className="mono">
                      <Ident value={c.exe} />
                    </span>{" "}
                    · {c.device_id} · {c.network_context} · {c.state === "capturing" ? `ends ${ago(c.ends_at)}` : `started ${ago(c.started_at)}`}
                  </div>
                </div>
                {c.state !== "closed" ? (
                  <button type="button" className="btn btn-quiet" onClick={() => void close(c.id)} disabled={mode === "live" && !canAct.ok}>
                    Close and review
                  </button>
                ) : c.candidate_id ? (
                  <button type="button" className="btn btn-quiet" onClick={() => go(`learning/c/${encodeURIComponent(c.candidate_id!)}`)}>
                    Candidate
                  </button>
                ) : null}
              </div>
            ))}
          </Card>
          <Card>
            <SectionTitle action={<Badge tone={v.data.review_queue.length ? "amber" : "neutral"}>{v.data.review_queue.length} to review</Badge>}>Candidates</SectionTitle>
            {v.data.review_queue.length === 0 ? <div className="small muted">Nothing waiting for review.</div> : v.data.review_queue.map((c) => <CandidateRow key={c.id} c={c} go={go} />)}
          </Card>
          <Card>
            <SectionTitle action={<Badge tone={v.data.drift_queue.length ? "amber" : "neutral"}>{v.data.drift_queue.length} in queue</Badge>}>Drift review</SectionTitle>
            <div className="small muted">New activity after approval never changes a baseline. It arrives here as a new candidate, with identity changes and unused entries listed.</div>
            {v.data.drift_queue.length === 0 ? <div className="small muted">No drift waiting.</div> : v.data.drift_queue.map((c) => <CandidateRow key={c.id} c={c} go={go} />)}
          </Card>
          <Card>
            <SectionTitle action={<span className="muted small">immutable</span>}>Reviewed baselines</SectionTitle>
            {v.data.baselines.length === 0 && <div className="small muted">No baseline approved yet.</div>}
            {v.data.baselines.map((b) => (
              <button key={b.id} type="button" className="learn-row learn-row-button" onClick={() => go(`learning/b/${encodeURIComponent(b.id)}`)}>
                <div className="learn-row-main">
                  <div className="learn-row-head">
                    <span className="learn-row-title">
                      <Ident value={exeName(b.exe)} />
                    </span>
                    {b.retired ? <Badge tone="neutral">retired</Badge> : <Badge tone="blue">{b.entries.length} entries</Badge>}
                  </div>
                  <div className="small muted">
                    {b.workflow ?? "imported"} · {b.device_id} · approved {ago(b.approved_at)}
                  </div>
                </div>
                <Icon name="chevron" size={16} className="row-chevron" />
              </button>
            ))}
          </Card>
        </>
      )}
    </div>
  );
}

/** Candidate review: the permission diff with its evidence. Accepting needs an owner sign-in; enforcing the resulting
 * baseline needs the owner key. Nothing is selected by default. */
export function CandidateReview({ id, go }: { id: string; go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const demo = [...demoLearning.review_queue, ...demoLearning.drift_queue].find((c) => c.id === id) ?? null;
  const v = useView<Candidate>(`/v1/learning/candidates/${encodeURIComponent(id)}`, demo);
  const [sel, setSel] = useState<number[]>([]);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const c = v.data;
  if (!c) return <div className="page">{v.error ? <Empty title="Candidate not found" icon="alert">{v.error}</Empty> : <div className="muted small">Loading…</div>}</div>;
  const toggle = (i: number) => setSel((s) => (s.includes(i) ? s.filter((x) => x !== i) : [...s, i]));
  const accept = async () => {
    setErr(null);
    const b = acceptBody(c, sel, ack);
    if ("refusal" in b) return setErr(b.refusal);
    if (mode === "demo") return say(`Demo: nothing was sent. Accepting ${b.accept.length} of ${c.entries.length} entries makes a new immutable baseline; it is enforced only after your owner key signs it.`);
    try {
      const base = await postLive<Baseline>(`/v1/learning/candidates/${encodeURIComponent(c.id)}/approve`, b);
      say(`Reviewed baseline recorded with ${base.entries.length} ${base.entries.length === 1 ? "entry" : "entries"}. Not enforced until you sign it with your owner key.`);
      go(`learning/b/${encodeURIComponent(base.id)}`);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const discard = async () => {
    if (mode === "demo") return say("Demo: nothing was sent.");
    try {
      await postLive(`/v1/learning/candidates/${encodeURIComponent(c.id)}/discard`, {});
      say("Discarded. Nothing was accepted; capture again for more evidence.");
      go("learning");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const open = c.status === "open";
  return (
    <div className="page">
      <a className="back" href="#/learning">
        ‹ Learning
      </a>
      <div className="page-head">
        <div className="eyebrow">
          {c.device_id} · {KIND[c.kind]}
        </div>
        <h1>
          <Ident value={exeName(c.exe)} />
        </h1>
        <p className="lede mono small">
          <Ident value={c.exe} />
          {c.signer ? ` · signer ${c.signer}` : " · no signer reported"}
        </p>
      </div>
      <Card>
        <SectionTitle action={<Badge tone={c.completeness === "complete" ? "green" : "amber"}>{c.completeness}</Badge>}>Evidence</SectionTitle>
        <Gaps reasons={c.incomplete_reasons} />
        {c.identity_changes.length > 0 && (
          <div className="learn-block">
            <div className="small strong">Identity changes in the same family</div>
            {c.identity_changes.map((x) => (
              <div key={`${x.exe}|${x.signer}`} className="small">
                <Badge tone="amber">not inherited</Badge>{" "}
                <span className="mono">
                  <Ident value={x.exe} />
                </span>
                {x.signer ? ` · signer ${x.signer}` : ""} · first {ago(x.first_at)}
              </div>
            ))}
          </div>
        )}
        {c.source && (
          <div className="small">
            Imported from <span className="mono">{c.source}</span>
            {c.assumptions && <> · assumes {Object.entries(c.assumptions).map(([k, val]) => `${k} ${String(val)}`).join(", ")}</>}
          </div>
        )}
        <div className="footnote">{c.note}</div>
      </Card>
      <Card>
        <SectionTitle action={<Badge tone={c.permission_diff.adds ? "amber" : "neutral"}>{c.permission_diff.adds} would broaden</Badge>}>Permission diff</SectionTitle>
        <div className="small muted">{c.permission_diff.baseline_id ? <>Against the current reviewed baseline <span className="mono">{c.permission_diff.baseline_id}</span>.</> : "No reviewed baseline for this identity yet: every accepted entry adds an exact allow."}</div>
        <div className="diff-list" role="group" aria-label="Proposed entries">
          {c.permission_diff.rows.map((r) => (
            <label key={r.index} className={`diff-row ${r.denied_only ? "diff-denied" : ""} ${r.unknown_destination ? "diff-unknown" : ""}`}>
              <input type="checkbox" checked={sel.includes(r.index)} onChange={() => toggle(r.index)} disabled={!open} aria-label={`Accept ${r.destination}${r.port ? `:${r.port}` : ""}`} />
              <span className="diff-sign" aria-hidden>
                {r.change === "adds" ? "+" : "="}
              </span>
              <span className="diff-main">
                <span className="mono diff-dest">
                  <Ident value={r.destination} kind="host" />
                  {r.port ? `:${r.port}` : ""}
                </span>
                <span className="small muted">
                  {r.transport ?? "any"} · seen {r.occurrences}× {r.change === "in_baseline" ? "· already in baseline" : ""}
                </span>
                {r.denied_only && <span className="small bad">Only ever refused. Accepting it does not override a deny: denies keep precedence.</span>}
                {r.unknown_destination && <span className="small bad">Destination not reported. It cannot become an exact rule.</span>}
              </span>
            </label>
          ))}
        </div>
        {c.permission_diff.removals.length > 0 && (
          <div className="learn-block">
            <div className="small strong">Proposed for removal</div>
            {c.permission_diff.removals.map((x) => (
              <div key={`${x.destination}:${x.port}`} className="small">
                <span className="diff-sign">−</span> <span className="mono">{x.destination}{x.port ? `:${x.port}` : ""}</span> <span className="muted">· {x.caveat}</span>
              </div>
            ))}
          </div>
        )}
        <div className="footnote">Repetition is shown as a count and never accepts anything. {c.permission_diff.note}</div>
      </Card>
      {open ? (
        <Card className="learn-accept">
          <SectionTitle action={<Badge tone="blue">owner</Badge>}>Accept into a reviewed baseline</SectionTitle>
          <div className="small">
            {sel.length} of {c.entries.length} selected. Accepting needs an owner sign-in and records an immutable baseline. It is not enforced: enforcing it is a broadening proposal your owner key must sign.
          </div>
          {c.completeness === "incomplete" && (
            <label className="check-row small">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I reviewed the gaps above and accept a partial baseline.
            </label>
          )}
          {err && <div className="small bad">{err}</div>}
          <div className="decision-actions">
            <button type="button" className="btn btn-primary" onClick={() => void accept()} disabled={(mode === "live" && !canAct.ok) || sel.length === 0}>
              Accept {sel.length || ""} selected
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => void discard()} disabled={mode === "live" && !canAct.ok}>
              More evidence needed
            </button>
          </div>
          {mode === "live" && canAct.reason && <div className="small muted">{canAct.reason}</div>}
        </Card>
      ) : (
        <Card>
          <div className="small muted">This candidate was {c.status}. A reviewed candidate cannot be accepted again.</div>
        </Card>
      )}
    </div>
  );
}

/** A reviewed baseline: immutable. Enforce it (owner key), review drift (a new candidate), or retire it. */
export function BaselineView({ id, go }: { id: string; go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const v = useView<Baseline>(`/v1/learning/baselines/${encodeURIComponent(id)}`, demoLearning.baselines.find((b) => b.id === id) ?? null);
  const [proposal, setProposal] = useState<WireProposal | null>(null);
  const b = v.data;
  if (!b) return <div className="page">{v.error ? <Empty title="Baseline not found" icon="alert">{v.error}</Empty> : <div className="muted small">Loading…</div>}</div>;
  const act = async (what: "propose" | "drift" | "retire") => {
    if (mode === "demo") return say(what === "propose" ? "Demo: nothing was sent. Enforcing prepares a proposal that only your owner key can authorize." : "Demo: nothing was sent.");
    try {
      if (what === "propose") setProposal(await postLive<WireProposal>(`/v1/learning/baselines/${encodeURIComponent(b.id)}/propose`, {}));
      if (what === "drift") {
        const r = await postLive<{ drift: boolean; note?: string; candidate?: Candidate }>(`/v1/learning/baselines/${encodeURIComponent(b.id)}/drift`, {});
        if (r.candidate) go(`learning/c/${encodeURIComponent(r.candidate.id)}`);
        else say(r.note ?? "No drift.");
      }
      if (what === "retire") {
        await postLive(`/v1/learning/baselines/${encodeURIComponent(b.id)}/retire`, { reason: "retired by owner from the web UI" });
        v.reload();
      }
    } catch (e) {
      say((e as Error).message);
    }
  };
  return (
    <div className="page">
      <a className="back" href="#/learning">
        ‹ Learning
      </a>
      <div className="page-head">
        <div className="eyebrow">Reviewed baseline · {b.device_id}</div>
        <h1>
          <Ident value={exeName(b.exe)} />
        </h1>
        <p className="lede small">
          {b.workflow ?? "imported"} · {b.network_context ?? "no network context"} · approved {ago(b.approved_at)} by {b.approved_by}
        </p>
      </div>
      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}
      <Card>
        <SectionTitle action={b.retired ? <Badge tone="neutral">retired</Badge> : <Badge tone="blue">immutable</Badge>}>Accepted entries</SectionTitle>
        {b.entries.map((x) => (
          <div key={`${x.destination}|${x.port}|${x.transport}`} className="small">
            <span className="mono">
              <Ident value={x.destination} kind="host" />
              {x.port ? `:${x.port}` : ""}
            </span>{" "}
            <span className="muted">· {x.transport ?? "any"}</span>
          </div>
        ))}
        <div className="footnote">
          Digest <span className="mono">{b.digest}</span>. A baseline is never edited; new activity becomes a new candidate.
          {b.supersedes && <> Supersedes {b.supersedes}.</>}
        </div>
      </Card>
      {!b.retired && (
        <Card>
          <SectionTitle>Enforce or review</SectionTitle>
          <div className="small muted">Enforcing adds exact allows for this executable through the normal policy path. It broadens access, so the signer needs your owner key; existing denies keep precedence.</div>
          <div className="decision-actions">
            <button type="button" className="btn btn-primary" onClick={() => void act("propose")} disabled={mode === "live" && !canAct.ok}>
              Enforce with owner key
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => void act("drift")} disabled={mode === "live" && !canAct.ok}>
              Review drift
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => void act("retire")} disabled={mode === "live" && !canAct.ok}>
              Retire
            </button>
          </div>
          {mode === "live" && canAct.reason && <div className="small muted">{canAct.reason}</div>}
        </Card>
      )}
    </div>
  );
}

function PackCard({ d, onProposed }: { d: PackDelta; onProposed: (p: WireProposal) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const [sel, setSel] = useState<string[]>([]);
  const toggle = (m: string) => setSel((s) => (s.includes(m) ? s.filter((x) => x !== m) : [...s, m]));
  const propose = async () => {
    if (!sel.length) return say("Choose the modules to enable. Nothing is enabled by default.");
    if (mode === "demo") return say("Demo: nothing was sent. Enabling modules prepares a broadening proposal your owner key must sign.");
    try {
      const r = await postLive<{ proposal: WireProposal }>("/v1/packs/propose", { pack: d.pack.id, modules: sel });
      onProposed(r.proposal);
    } catch (e) {
      say((e as Error).message);
    }
  };
  return (
    <Card className="pack-card">
      <SectionTitle action={<Badge tone="neutral">{`${d.pack.id}@${d.pack.version}`}</Badge>}>{d.pack.name}</SectionTitle>
      <div className="small muted">{d.pack.description}</div>
      <div className="pack-effective">
        <div>
          <span className="sim-num">{d.effective.modules_to_enable}</span>
          <span className="muted small">modules not enabled</span>
        </div>
        <div>
          <span className="sim-num">{d.effective.newly_allowed.length}</span>
          <span className="muted small">new destinations</span>
        </div>
        <div>
          <span className={`sim-num ${d.effective.unsupported_cells ? "bad" : ""}`}>{d.effective.unsupported_cells}</span>
          <span className="muted small">unsupported cells</span>
        </div>
      </div>
      {d.problems.length > 0 && <div className="small bad">Pack problems: {d.problems.join("; ")}</div>}
      {d.modules.map((m) => (
        <div key={m.id} className="pack-module">
          <label className="check-row">
            <input type="checkbox" checked={sel.includes(m.id)} onChange={() => toggle(m.id)} disabled={m.enabled} aria-label={`Enable ${m.name}`} />
            <span className="strong">{m.name}</span>
            {m.enabled ? <Badge tone="green">enabled</Badge> : m.optional ? <Badge tone="neutral">optional</Badge> : null}
          </label>
          <div className="small muted">{m.rationale}</div>
          <div className="small">
            {m.enabled ? (
              <span className="muted">Already in the current policy: no change.</span>
            ) : (
              <>
                Adds{" "}
                {m.newly_allowed.length ? (
                  m.newly_allowed.map((h) => (
                    <span key={h} className="chip chip-allow">
                      <span className="mono">{h}</span>
                    </span>
                  ))
                ) : (
                  <span className="muted">no destination not already named in policy</span>
                )}{" "}
                {m.destinations.ports.length > 0 && <span className="muted">on {m.destinations.transport ?? "any"} {m.destinations.ports.join(", ")}</span>}
              </>
            )}
          </div>
          <div className="cell-grid" role="table" aria-label={`${m.name}: support per device`}>
            {m.cells.map((c) => (
              <div key={c.device_id} className={`cell ${c.takes_effect ? "" : "cell-off"}`} role="row">
                <span className="small strong" role="cell">
                  {c.device}
                </span>
                <span role="cell">
                  <Badge tone={SUPPORT_TONE[c.support]}>{c.support}</Badge>
                </span>
                <span className="small muted" role="cell">
                  {c.takes_effect ? "takes effect" : `skipped with a report: ${c.missing.map((x) => `${x.capability.replace(/_/g, " ")} ${x.support}`).join(", ")}`}
                </span>
              </div>
            ))}
            {m.cells.length === 0 && <div className="small muted">No enrolled endpoint to apply it to.</div>}
          </div>
          {!m.enabled && <div className="small muted">If omitted: {m.expected_breakage_if_omitted}</div>}
        </div>
      ))}
      <div className="decision-actions">
        <button type="button" className="btn btn-primary" onClick={() => void propose()} disabled={(mode === "live" && !canAct.ok) || sel.length === 0}>
          Propose {sel.length || ""} module{sel.length === 1 ? "" : "s"}
        </button>
      </div>
      <div className="footnote">{d.note}</div>
    </Card>
  );
}

export function Packs() {
  const { fetchLive, mode } = useStore();
  const list = useView<PackSummary[]>("/v1/packs", null);
  const [deltas, setDeltas] = useState<PackDelta[] | null>(mode === "demo" ? demoPacks : null);
  const [proposal, setProposal] = useState<WireProposal | null>(null);
  useEffect(() => {
    if (mode === "demo" || !list.data) return;
    let live = true;
    void Promise.all(list.data.map((p) => fetchLive<PackDelta>(`/v1/packs/${encodeURIComponent(p.id)}/delta`))).then((d) => live && setDeltas(d), () => live && setDeltas([]));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.data, mode]);
  return (
    <div className="page">
      <LearningNav active="packs" />
      <div className="page-head">
        <h1>Workflow packs</h1>
        <p className="lede">Maintained rule modules for common workflows. Each shows what it would add to your policy and where it would not take effect. A pack's signature is not your consent: enabling modules needs your owner key.</p>
      </div>
      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}
      {mode === "live" && list.error && (
        <Card>
          <div className="small bad">Could not load packs: {list.error}</div>
        </Card>
      )}
      {!deltas ? <div className="muted small">Loading…</div> : deltas.map((d) => <PackCard key={d.pack.id} d={d} onProposed={setProposal} />)}
    </div>
  );
}
