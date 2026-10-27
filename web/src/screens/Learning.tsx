/**
 * W14 review screens (MASTER_ROADMAP §9.4, §9.7): learning capture, candidate review with the permission diff and its
 * evidence, baseline accept (owner sign-in) and enforce (owner key), the drift queue, and the pack browser with each
 * pack's effective delta and unsupported cells. Learning produces a proposal, never trust.
 */
import { useEffect, useState } from "react";
import { Actions, Button, Card, Details, EmptyState, Facts, Fine, Icon, Ident, Page, StatusChip, SubNav, RULES_NAV, type Tone } from "../components/ui";
import { useData, useStore } from "../data/store";
import type { WireProposal } from "../data/api";
import { acceptBody, demoLearning, demoPacks, gapKind, SUPPORT_TONE, type Baseline, type Candidate, type LearningOverview, type PackDelta, type PackSummary } from "../data/learning";
import { ago, SUPPORT, until } from "../format";
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

/** Kept for callers outside this file: the Rules / Learn / Rule packs tabs. */
export function LearningNav({ active }: { active: "rules" | "learning" | "packs" }) {
  return <SubNav items={RULES_NAV} active={active === "packs" ? "learning/packs" : active} label="Rules" />;
}

const GAP_LABEL: Record<string, [Tone, string]> = { identity: ["red", "Unknown app"], lost: ["amber", "Lost reports"], pending: ["amber", "Still arriving"], import: ["amber", "Not seen here"] };

function Gaps({ reasons }: { reasons: string[] }) {
  if (!reasons.length) return <p className="tone-green">Nothing missing: no lost reports, nothing still arriving, and every connection came from a known app.</p>;
  return (
    <ul className="gap-list" aria-label="Why the recording is incomplete">
      {reasons.map((r) => {
        const [tone, label] = GAP_LABEL[gapKind(r)] ?? ["amber", "Gap"];
        return (
          <li key={r}>
            <StatusChip tone={tone}>{label}</StatusChip>
            <Ident value={r} kind="text" />
          </li>
        );
      })}
    </ul>
  );
}

const exeName = (exe: string) => exe.split("/").pop() || exe;
const KIND: Record<Candidate["kind"], string> = { capture: "from a recording", drift: "new since approval", import: "imported" };

function CandidateRow({ c, go }: { c: Candidate; go: (to: string) => void }) {
  return (
    <button type="button" className="row row-link" onClick={() => go(`learning/c/${encodeURIComponent(c.id)}`)}>
      <span className="row-main">
        <span className="row-title">
          <Ident value={exeName(c.exe)} /> <StatusChip tone={c.completeness === "complete" ? "green" : "amber"}>{c.completeness === "complete" ? "Complete" : "Incomplete"}</StatusChip>
        </span>
        <span className="row-sub">
          {c.permission_diff.adds} would allow more · {c.entries.length} places · {KIND[c.kind]} · {ago(c.created_at)}
          {c.identity_changes.length > 0 && ` · ${c.identity_changes.length} other version`}
          {c.removal_proposals.length > 0 && ` · ${c.removal_proposals.length} unused`}
        </span>
      </span>
      <Icon name="chevron" size={16} className="row-chevron" />
    </button>
  );
}

/** Start a recording: one device, one exact app file, one named job and network, a time limit. */
function CaptureControl({ onStarted, limits }: { onStarted: () => void; limits: LearningOverview["limits"] }) {
  const data = useData();
  const { postLive, mode, canAct, say } = useStore();
  const enforcing = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos");
  const [f, setF] = useState({ device_id: enforcing[0]?.id ?? "", exe: "", workflow: "", network_context: "", hours: "1" });
  const [err, setErr] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const start = async () => {
    setErr(null);
    if (!f.exe.startsWith("/")) return setErr("Enter the app's exact file path. A name alone could be any program.");
    if (!f.workflow.trim() || !f.network_context.trim()) return setErr("Say what the app is doing and on which network: a normal day and an install are different recordings.");
    const hours = Number(f.hours);
    if (!(hours > 0 && hours <= limits.max_capture_hours)) return setErr(`A recording lasts at most ${limits.max_capture_hours} hours.`);
    if (mode === "demo") return say("Demo: nothing was recorded. With a real controller, Moat records one time-limited window while your current rules stay on.");
    try {
      const r = await postLive<{ id: string; note: string }>("/v1/learning/captures", { ...f, hours });
      say(r.note);
      onStarted();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <Card className="learn-capture" title="Record an app" action={<StatusChip tone="blue" icon="clock">Time-limited</StatusChip>}>
      <p className="muted">Moat watches one app do one job, so you can review what it reached. Your current rules, including every block, stay on while it records. Nothing it reaches is trusted until you review it.</p>
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
          App file (exact path)
          <input className="mono" value={f.exe} onChange={set("exe")} placeholder="/usr/bin/npm" spellCheck={false} />
        </label>
        <label>
          What it&apos;s doing
          <input value={f.workflow} onChange={set("workflow")} placeholder="npm install" />
        </label>
        <label>
          Network
          <input value={f.network_context} onChange={set("network_context")} placeholder="home Wi-Fi" />
        </label>
        <label>
          Hours (at most {limits.max_capture_hours})
          <input type="number" min={1} max={limits.max_capture_hours} value={f.hours} onChange={set("hours")} />
        </label>
      </div>
      {err && <p className="error">{err}</p>}
      <Actions>
        <Button kind="primary" onClick={start} disabled={mode === "live" && !canAct.ok}>
          Start recording
        </Button>
      </Actions>
      {mode === "live" && canAct.reason && <Fine>{canAct.reason}</Fine>}
    </Card>
  );
}

/** Learn: "What should I allow for an app I trust?" Reviews waiting come first, then recording. */
export function Learning({ go }: { go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const v = useView<LearningOverview>("/v1/learning", demoLearning);
  const close = async (id: string) => {
    if (mode === "demo") return say("Demo: nothing was sent. Stopping a recording turns it into a review.");
    try {
      const c = await postLive<Candidate>(`/v1/learning/captures/${encodeURIComponent(id)}/close`, {});
      go(`learning/c/${encodeURIComponent(c.id)}`);
    } catch (e) {
      say((e as Error).message);
    }
  };
  return (
    <Page title="Learn what an app needs" lede="Record an app doing one job, then tick what it may reach. Nothing is allowed until you review it and sign it with your owner key." nav={<LearningNav active="learning" />}>
      {v.error && !v.data && <p className="error">Couldn&apos;t load: {v.error}</p>}
      {v.data && (
        <>
          <Card title="Ready to review" action={<StatusChip tone={v.data.review_queue.length ? "amber" : "neutral"}>{v.data.review_queue.length} to review</StatusChip>}>
            {v.data.review_queue.length === 0 ? <p className="muted">Nothing waiting. Stop a recording to review it.</p> : <div className="list">{v.data.review_queue.map((c) => <CandidateRow key={c.id} c={c} go={go} />)}</div>}
          </Card>
          <Card title="New since approval" action={<StatusChip tone={v.data.drift_queue.length ? "amber" : "neutral"}>{v.data.drift_queue.length} in queue</StatusChip>}>
            <p className="muted">New activity never changes an approved list. It comes here as a new review.</p>
            {v.data.drift_queue.length > 0 && <div className="list">{v.data.drift_queue.map((c) => <CandidateRow key={c.id} c={c} go={go} />)}</div>}
          </Card>
          <CaptureControl onStarted={v.reload} limits={v.data.limits} />
          {v.data.captures.length > 0 && (
            <Card title="Recordings" action={<span className="muted">{v.data.captures.filter((c) => c.state !== "closed").length} open</span>}>
              <div className="list">
                {v.data.captures.map((c) => (
                  <div key={c.id} className="row">
                    <span className="row-main">
                      <span className="row-title">
                        <Ident value={c.workflow} kind="text" />{" "}
                        <StatusChip tone={c.state === "capturing" ? "blue" : c.state === "window_ended" ? "amber" : "neutral"} icon={c.state === "capturing" ? "dot" : undefined}>
                          {c.state === "capturing" ? "Recording" : c.state === "window_ended" ? "Time's up" : "Closed"}
                        </StatusChip>
                      </span>
                      <span className="row-sub">
                        <Ident value={exeName(c.exe)} /> · <Ident value={c.device_id} /> · <Ident value={c.network_context} kind="text" /> · {c.state === "capturing" ? (Date.parse(c.ends_at) > Date.now() ? until(c.ends_at) : `ended ${ago(c.ends_at)}`) : `started ${ago(c.started_at)}`}
                      </span>
                    </span>
                    {c.state !== "closed" ? (
                      <Button onClick={() => void close(c.id)} disabled={mode === "live" && !canAct.ok}>
                        Stop and review
                      </Button>
                    ) : c.candidate_id ? (
                      <Button kind="quiet" onClick={() => go(`learning/c/${encodeURIComponent(c.candidate_id!)}`)}>
                        Open review
                      </Button>
                    ) : null}
                  </div>
                ))}
              </div>
            </Card>
          )}
          {v.data.baselines.length > 0 && (
            <Card title="Approved lists" action={<span className="muted">never edited</span>}>
              <div className="list">
                {v.data.baselines.map((b) => (
                  <button key={b.id} type="button" className="row row-link" onClick={() => go(`learning/b/${encodeURIComponent(b.id)}`)}>
                    <span className="row-main">
                      <span className="row-title">
                        <Ident value={exeName(b.exe)} /> {b.retired ? <StatusChip>Retired</StatusChip> : <StatusChip tone="blue" icon={null}>{b.entries.length} places</StatusChip>}
                      </span>
                      <span className="row-sub">
                        <Ident value={b.workflow ?? "imported"} kind="text" /> · <Ident value={b.device_id} /> · approved {ago(b.approved_at)}
                      </span>
                    </span>
                    <Icon name="chevron" size={16} className="row-chevron" />
                  </button>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </Page>
  );
}

/** A review: what the app tried to reach while recorded. Approving needs an owner sign-in; turning the resulting list
 * on needs the owner key. Nothing is ticked by default. */
export function CandidateReview({ id, go }: { id: string; go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const demo = [...demoLearning.review_queue, ...demoLearning.drift_queue].find((c) => c.id === id) ?? null;
  const v = useView<Candidate>(`/v1/learning/candidates/${encodeURIComponent(id)}`, demo);
  const [sel, setSel] = useState<number[]>([]);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const c = v.data;
  if (!c)
    return (
      <Page title="Review" back={{ label: "Learn", to: "learning" }}>
        {v.error ? <EmptyState title="Review not found" icon="alert">{v.error}</EmptyState> : <div className="muted">Loading…</div>}
      </Page>
    );
  const toggle = (i: number) => setSel((s) => (s.includes(i) ? s.filter((x) => x !== i) : [...s, i]));
  const accept = async () => {
    setErr(null);
    const b = acceptBody(c, sel, ack);
    if ("refusal" in b) return setErr(b.refusal);
    if (mode === "demo") return say(`Demo: nothing was sent. Accepting ${b.accept.length} of ${c.entries.length} places saves a new approved list; it takes effect only after your owner key signs it.`);
    try {
      const base = await postLive<Baseline>(`/v1/learning/candidates/${encodeURIComponent(c.id)}/approve`, b);
      say(`Approved list saved with ${base.entries.length} ${base.entries.length === 1 ? "place" : "places"}. It isn't on until you sign it with your owner key.`);
      go(`learning/b/${encodeURIComponent(base.id)}`);
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const discard = async () => {
    if (mode === "demo") return say("Demo: nothing was sent.");
    try {
      await postLive(`/v1/learning/candidates/${encodeURIComponent(c.id)}/discard`, {});
      say("Discarded. Nothing was accepted; record again to see more.");
      go("learning");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const open = c.status === "open";
  return (
    <Page
      back={{ label: "Learn", to: "learning" }}
      eyebrow={
        <>
          <Ident value={c.device_id} /> · {KIND[c.kind]}
        </>
      }
      title={<Ident value={exeName(c.exe)} />}
    >
      <Card title="What was recorded" action={<StatusChip tone={c.completeness === "complete" ? "green" : "amber"}>{c.completeness === "complete" ? "Complete" : "Incomplete"}</StatusChip>}>
        <Gaps reasons={c.incomplete_reasons} />
        {c.identity_changes.length > 0 && (
          <div className="stack-tight">
            <strong>Other versions of this app</strong>
            {c.identity_changes.map((x) => (
              <span key={`${x.exe}|${x.signer}`}>
                <StatusChip tone="amber">Separate app</StatusChip> <Ident value={x.exe} mono />
                {x.signer ? ` · signed by ${x.signer}` : ""} · first {ago(x.first_at)}. Nothing carries over.
              </span>
            ))}
          </div>
        )}
        <Details summary="Technical details">
          <Facts
            rows={[
              ["App file", <Ident key="e" value={c.exe} mono />],
              ["Signer", c.signer ?? "none reported"],
              ...(c.source ? ([["Imported from", <span key="s" className="mono">{c.source}</span>]] as [string, JSX.Element][]) : []),
              ...(c.assumptions ? ([["Assumes", Object.entries(c.assumptions).map(([k, val]) => `${k} ${String(val)}`).join(", ")]] as [string, string][]) : []),
            ]}
          />
          <Fine>
            <Ident value={c.note} kind="text" />
          </Fine>
        </Details>
      </Card>
      <Card title="What it tried to reach" action={<StatusChip tone={c.permission_diff.adds ? "amber" : "neutral"}>{c.permission_diff.adds} would allow more</StatusChip>}>
        <p className="muted">{c.permission_diff.baseline_id ? "Compared with this app's current approved list." : "This app has no approved list yet: every place you tick is allowed exactly."}</p>
        <div className="diff-list" role="group" aria-label="Places to allow">
          {c.permission_diff.rows.map((r) => (
            <label key={r.index} className={`diff-row ${r.denied_only ? "diff-denied" : ""} ${r.unknown_destination ? "diff-unknown" : ""}`}>
              <input type="checkbox" checked={sel.includes(r.index)} onChange={() => toggle(r.index)} disabled={!open} aria-label={`Accept ${r.destination}${r.port ? `:${r.port}` : ""}`} />
              <span className="row-main">
                <span className="row-title">
                  <Ident value={`${r.destination}${r.port ? `:${r.port}` : ""}`} kind="host" mono />
                </span>
                <span className="row-sub">
                  seen {r.occurrences} {r.occurrences === 1 ? "time" : "times"}
                  {r.change === "in_baseline" ? " · already allowed" : ""}
                </span>
                {r.denied_only && <span className="row-sub tone-red">Only ever blocked. Ticking it doesn&apos;t override a block: blocks always win.</span>}
                {r.unknown_destination && <span className="row-sub tone-red">Address not reported, so it can&apos;t become a rule.</span>}
              </span>
            </label>
          ))}
        </div>
        {c.permission_diff.removals.length > 0 && (
          <div className="stack-tight">
            <strong>Not used lately</strong>
            {c.permission_diff.removals.map((x) => (
              <span key={`${x.destination}:${x.port}`}>
                <Ident value={`${x.destination}${x.port ? `:${x.port}` : ""}`} kind="host" mono /> <span className="muted">· <Ident value={x.caveat} kind="text" /></span>
              </span>
            ))}
          </div>
        )}
        <Fine>Seeing something many times never allows it. <Ident value={c.permission_diff.note} kind="text" /></Fine>
      </Card>
      {open ? (
        <Card className="learn-accept" title="Accept what you ticked" action={<StatusChip tone="blue" icon="shield">Owner</StatusChip>}>
          <p>
            {sel.length} of {c.entries.length} ticked. Accepting needs an owner sign-in and saves an approved list that never changes. It doesn&apos;t take effect yet: turning it on allows more, so your owner key must sign it.
          </p>
          {c.completeness === "incomplete" && (
            <label className="check-row">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I reviewed the gaps above and accept a partial list.
            </label>
          )}
          {err && <p className="error">{err}</p>}
          <Actions>
            <Button kind="primary" onClick={() => void accept()} disabled={(mode === "live" && !canAct.ok) || sel.length === 0}>
              Accept {sel.length || ""} selected
            </Button>
            <Button kind="quiet" onClick={() => void discard()} disabled={mode === "live" && !canAct.ok}>
              Record more first
            </Button>
          </Actions>
          {mode === "live" && canAct.reason && <Fine>{canAct.reason}</Fine>}
        </Card>
      ) : (
        <Card>
          <p className="muted">This review was {c.status}. It can&apos;t be accepted again.</p>
        </Card>
      )}
    </Page>
  );
}

/** An approved list: never edited. Turn it on (owner key), check for new activity (a new review), or retire it. */
export function BaselineView({ id, go }: { id: string; go: (to: string) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const v = useView<Baseline>(`/v1/learning/baselines/${encodeURIComponent(id)}`, demoLearning.baselines.find((b) => b.id === id) ?? null);
  const [proposal, setProposal] = useState<WireProposal | null>(null);
  const b = v.data;
  if (!b)
    return (
      <Page title="Approved list" back={{ label: "Learn", to: "learning" }}>
        {v.error ? <EmptyState title="Approved list not found" icon="alert">{v.error}</EmptyState> : <div className="muted">Loading…</div>}
      </Page>
    );
  const act = async (what: "propose" | "drift" | "retire") => {
    if (mode === "demo") return say(what === "propose" ? "Demo: nothing was sent. Turning it on prepares a change only your owner key can sign." : "Demo: nothing was sent.");
    try {
      if (what === "propose") setProposal(await postLive<WireProposal>(`/v1/learning/baselines/${encodeURIComponent(b.id)}/propose`, {}));
      if (what === "drift") {
        const r = await postLive<{ drift: boolean; note?: string; candidate?: Candidate }>(`/v1/learning/baselines/${encodeURIComponent(b.id)}/drift`, {});
        if (r.candidate) go(`learning/c/${encodeURIComponent(r.candidate.id)}`);
        else say(r.note ?? "Nothing new.");
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
    <Page
      back={{ label: "Learn", to: "learning" }}
      eyebrow={
        <>
          Approved list · <Ident value={b.device_id} />
        </>
      }
      title={<Ident value={exeName(b.exe)} />}
      lede={<><Ident value={b.workflow ?? "imported"} kind="text" /> · approved {ago(b.approved_at)} by <Ident value={b.approved_by} /></>}
    >
      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}
      <Card title="Allowed places" action={b.retired ? <StatusChip>Retired</StatusChip> : <StatusChip tone="blue" icon={null}>Never edited</StatusChip>}>
        <div className="list">
          {b.entries.map((x) => (
            <div key={`${x.destination}|${x.port}|${x.transport}`} className="row">
              <span className="row-main">
                <span className="row-title">
                  <Ident value={`${x.destination}${x.port ? `:${x.port}` : ""}`} kind="host" mono />
                </span>
              </span>
            </div>
          ))}
        </div>
        <Fine>An approved list is never edited; new activity becomes a new review.</Fine>
        <Details summary="Technical details">
          <Facts
            rows={[
              ["Digest", <span key="d" className="mono">{b.digest}</span>],
              ["Network", b.network_context ?? "none given"],
              ...(b.supersedes ? ([["Replaces", b.supersedes]] as [string, string][]) : []),
            ]}
          />
        </Details>
      </Card>
      {!b.retired && (
        <Card title="Turn it on">
          <p className="muted">Turning it on allows exactly these places for this app, through your normal rules. It allows more, so your owner key must sign it; your blocks still win.</p>
          <Actions>
            <Button kind="primary" onClick={() => void act("propose")} disabled={mode === "live" && !canAct.ok}>
              Turn on with owner key
            </Button>
            <Button onClick={() => void act("drift")} disabled={mode === "live" && !canAct.ok}>
              Check for new activity
            </Button>
            <Button kind="quiet" onClick={() => void act("retire")} disabled={mode === "live" && !canAct.ok}>
              Retire
            </Button>
          </Actions>
          {mode === "live" && canAct.reason && <Fine>{canAct.reason}</Fine>}
        </Card>
      )}
    </Page>
  );
}

function PackCard({ d, onProposed }: { d: PackDelta; onProposed: (p: WireProposal) => void }) {
  const { postLive, mode, canAct, say } = useStore();
  const [sel, setSel] = useState<string[]>([]);
  const toggle = (m: string) => setSel((s) => (s.includes(m) ? s.filter((x) => x !== m) : [...s, m]));
  const propose = async () => {
    if (!sel.length) return say("Choose the parts to turn on. Nothing is on by default.");
    if (mode === "demo") return say("Demo: nothing was sent. Turning parts on prepares a change your owner key must sign.");
    try {
      const r = await postLive<{ proposal: WireProposal }>("/v1/packs/propose", { pack: d.pack.id, modules: sel });
      onProposed(r.proposal);
    } catch (e) {
      say((e as Error).message);
    }
  };
  return (
    <Card className="pack-card" title={d.pack.name}>
      <p className="muted">
        <Ident value={d.pack.description} kind="text" />
      </p>
      <div className="stats">
        <div className="stat">
          <div className="stat-label">Parts not on yet</div>
          <div className="stat-value">{d.effective.modules_to_enable}</div>
        </div>
        <div className="stat">
          <div className="stat-label">New places</div>
          <div className="stat-value">{d.effective.newly_allowed.length}</div>
        </div>
        <div className={`stat ${d.effective.unsupported_cells ? "stat-amber" : ""}`}>
          <div className="stat-label">Won&apos;t apply on a device</div>
          <div className="stat-value">{d.effective.unsupported_cells}</div>
        </div>
      </div>
      {d.problems.length > 0 && <p className="error">Problems with this pack: {d.problems.join("; ")}</p>}
      {d.modules.map((m) => {
        const off = m.cells.filter((c) => !c.takes_effect);
        return (
          <div key={m.id} className="pack-module">
            <label className="check-row">
              <input type="checkbox" checked={sel.includes(m.id)} onChange={() => toggle(m.id)} disabled={m.enabled} aria-label={`Turn on ${m.name}`} />
              <strong>{m.name}</strong>
              {m.enabled ? <StatusChip tone="green">On</StatusChip> : m.optional ? <StatusChip>Optional</StatusChip> : null}
            </label>
            <span className="muted">
              <Ident value={m.rationale} kind="text" />
            </span>
            <span>
              {m.enabled ? (
                <span className="muted">Already in your rules: no change.</span>
              ) : m.newly_allowed.length ? (
                <>
                  Adds{" "}
                  {m.newly_allowed.map((h, k) => (
                    <span key={h}>
                      {k > 0 && ", "}
                      <Ident value={h} kind="host" mono />
                    </span>
                  ))}
                </>
              ) : (
                <span className="muted">Adds no place your rules don&apos;t already name.</span>
              )}
            </span>
            {off.length > 0 && (
              <span className="tone-amber">
                <Icon name="alert" size={12} /> Won&apos;t apply on {off.map((c) => c.device).join(", ")}
              </span>
            )}
            {m.cells.length === 0 && <span className="muted">No computer to apply it to yet.</span>}
            {!m.enabled && (
              <span className="muted">
                If left off: <Ident value={m.expected_breakage_if_omitted} kind="text" />
              </span>
            )}
            {m.cells.length > 0 && (
              <Details summary="Where it applies">
                <div className="cell-grid" role="table" aria-label={`${m.name}: where it applies`}>
                  {m.cells.map((c) => (
                    <div key={c.device_id} className={`cell ${c.takes_effect ? "" : "cell-off"}`} role="row">
                      <strong role="cell">{c.device}</strong>
                      <span role="cell">
                        <StatusChip tone={SUPPORT_TONE[c.support] as Tone}>{c.support === "unknown" ? "Unknown" : SUPPORT[c.support].label}</StatusChip>
                      </span>
                      <span className="muted" role="cell">
                        {c.takes_effect ? "takes effect" : `skipped with a report: ${c.missing.map((x) => `${x.capability.replace(/_/g, " ")} ${x.support}`).join(", ")}`}
                      </span>
                    </div>
                  ))}
                </div>
                {m.destinations.ports.length > 0 && <Fine>Ports: {m.destinations.transport ?? "any"} {m.destinations.ports.join(", ")}</Fine>}
              </Details>
            )}
          </div>
        );
      })}
      <Actions>
        <Button kind="primary" onClick={() => void propose()} disabled={(mode === "live" && !canAct.ok) || sel.length === 0}>
          Turn on {sel.length || ""} {sel.length === 1 ? "part" : "parts"}
        </Button>
      </Actions>
      <Fine>
        <Ident value={d.note} kind="text" />
      </Fine>
      <Details summary="Technical details">
        <span className="mono">{`${d.pack.id}@${d.pack.version}`}</span>
      </Details>
    </Card>
  );
}

/** Rule packs: "Which ready-made rules fit my work?" Nothing is on by default; turning a part on needs the owner key. */
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
    <Page title="Rule packs" lede="Ready-made rules for common work. Nothing is on until you choose, and turning a part on needs your owner key." nav={<LearningNav active="packs" />}>
      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}
      {mode === "live" && list.error && <p className="error">Couldn&apos;t load rule packs: {list.error}</p>}
      {!deltas ? <div className="muted">Loading…</div> : deltas.map((d) => <PackCard key={d.pack.id} d={d} onProposed={setProposal} />)}
    </Page>
  );
}
