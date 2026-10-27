import { LearningNav } from "./Learning";
import { useState } from "react";
import { Badge, Card, Icon, Ident, SectionTitle } from "../components/ui";
import type { WireProposal } from "../data/api";
import { useData, useStore } from "../data/store";
import type { RevisionState } from "../data/types";
import { ago, until } from "../format";

const STATES: RevisionState[] = ["approved", "distributed", "received", "applied", "verified"];

const AUTH: Record<string, [string, string]> = { owner_key: ["blue", "owner key"], narrowing: ["neutral", "narrowing"], temporary_grant_overlay: ["green", "grant overlay"], delegated_issuer: ["green", "delegated approval"] };

/** A prepared proposal (a rollback, a reviewed baseline or pack modules). Broadening needs an owner-key signature made off this page. */
export function ProposalPanel({ p, onDone }: { p: WireProposal; onDone: () => void }) {
  const { approve, canAct } = useStore();
  const [auth, setAuth] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setErr(null);
    let a: { key_id: string; signature: string } | null = null;
    if (p.broadening) {
      try {
        const j = JSON.parse(auth) as { key_id?: unknown; signature?: unknown };
        if (typeof j.key_id !== "string" || typeof j.signature !== "string") throw new Error("needs key_id and signature");
        a = { key_id: j.key_id, signature: j.signature };
      } catch (e) {
        setErr(`Paste the JSON printed by owner-authorize (${(e as Error).message}).`);
        return;
      }
    }
    setBusy(true);
    try {
      await approve(p.id, a);
      onDone();
    } catch {
      /* the store reported it */
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card className="proposal">
      <SectionTitle action={<Badge tone={p.broadening ? "amber" : "neutral"}>{p.broadening ? "broadens access" : "narrowing"}</Badge>}>Prepared, not signed</SectionTitle>
      <div className="small">
        Proposal <Ident value={p.id} mono /> {p.rollback_of != null ? <>restores revision {p.rollback_of}'s rules as a new revision on top of {p.base_revision}.</> : <>({p.message}) builds on revision {p.base_revision}.</>} Nothing changes on any device until it is signed and each device reports it applied.
      </div>
      {p.broadening ? (
        <>
          <div className="small muted">This broadens access, so the signer needs your owner key. The key never belongs in a browser. On the machine that holds it, run:</div>
          <pre className="code">{`moat-controller owner-authorize <owner.key> ${p.authorization_subject} ${p.authorization_digest}`}</pre>
          <label className="small" htmlFor={`auth-${p.id}`}>
            Paste the printed authorization
          </label>
          <textarea id={`auth-${p.id}`} className="input mono" rows={3} value={auth} onChange={(e) => setAuth(e.target.value)} spellCheck={false} />
        </>
      ) : (
        <div className="small muted">Narrowing changes are signed without an owner key.</div>
      )}
      {err && <div className="small bad">{err}</div>}
      <div className="decision-actions">
        <button type="button" className="btn btn-primary" disabled={!canAct.ok || busy || (p.broadening && !auth.trim())} onClick={submit}>
          {busy ? "Signing…" : "Ask the signer to sign"}
        </button>
        <button type="button" className="btn btn-quiet" onClick={onDone}>
          Close
        </button>
      </div>
      {canAct.reason && <div className="small muted">{canAct.reason}</div>}
    </Card>
  );
}

export function Rules({ go }: { go: (to: string) => void }) {
  const data = useData();
  const { rollback, canAct, mode } = useStore();
  const [openRev, setOpenRev] = useState<number>(data.revisions[0]?.revision ?? 0);
  const [proposal, setProposal] = useState<WireProposal | null>(null);
  const sim = data.simulation;
  return (
    <div className="page">
      <LearningNav active="rules" />
      <div className="page-head">
        <h1>Rules</h1>
        <p className="lede">Policy lives in Git and is signed by a separate signer. Broadening changes need your owner key; agents can prepare a diff but never authorize one.</p>
      </div>

      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}

      {sim ? (
      <Card className="sim">
        <SectionTitle action={<Badge tone="amber">proposal · not signed</Badge>}>Simulate before deploying</SectionTitle>
        <div className="sim-title">{sim.title}</div>
        <div className="sim-stats">
          <div>
            <span className="sim-num bad">{sim.newlyBlocked}</span>
            <span className="muted small">newly blocked</span>
          </div>
          <div>
            <span className="sim-num">{sim.newlyAllowed}</span>
            <span className="muted small">newly allowed</span>
          </div>
          <div>
            <span className="sim-num">{sim.observations.toLocaleString()}</span>
            <span className="muted small">flows replayed</span>
          </div>
        </div>
        <div className="sim-changes">
          {sim.changed.map((c, k) => (
            <div key={k} className="sim-change">
              <span className="mono small">{c.destination}</span>
              <span className="muted small">
                {c.app} · {c.device}
              </span>
              <span className="sim-arrow small">
                <span className="muted">{c.before}</span> → <span className="bad">{c.after}</span>
              </span>
            </div>
          ))}
        </div>
        <div className="sim-platforms">
          {sim.platforms.map((p) => (
            <div key={p.adapter} className="sim-platform">
              <Icon name={p.compiles ? "check" : "x"} size={14} className={p.compiles ? "ok" : "bad"} />
              <span>{p.adapter}</span>
              <span className="muted small">{p.compiles ? "compiles" : p.note}</span>
            </div>
          ))}
        </div>
        {sim.unobserved.length > 0 && <div className="muted small">Never observed: {sim.unobserved.join(", ")}</div>}
        {sim.unacknowledged.length > 0 && <div className="muted small">Not acknowledging the current revision: {sim.unacknowledged.join(", ")}</div>}
        <div className="footnote">{sim.disclaimer}</div>
      </Card>
      ) : (
        <Card>
          <SectionTitle>Simulate before deploying</SectionTitle>
          <div className="small muted">No open proposal. Prepare one with <span className="mono">moat-controller</span> or an agent proposal; its replay against recorded flows appears here before anything is signed.</div>
        </Card>
      )}

      {data.grants.length > 0 && (
        <>
          <SectionTitle>Temporary grants</SectionTitle>
          <div className="stack">
            {data.grants.map((g) => (
              <Card key={g.id} className="grant">
                <Icon name="clock" size={16} />
                <div>
                  <div className="small">
                    <Ident value={g.destination} kind="host" mono />
                  </div>
                  <div className="muted small">
                    <Ident value={g.scope} /> · by <Ident value={g.by} />
                  </div>
                </div>
                <Badge tone="green">{until(g.expiresAt)}</Badge>
              </Card>
            ))}
          </div>
        </>
      )}

      <SectionTitle>Revisions</SectionTitle>
      <div className="stack">
        {data.revisions.map((r) => {
          const open = openRev === r.revision;
          return (
            <Card key={r.revision} className={`rev ${open ? "rev-open" : ""}`}>
              <button type="button" className="rev-head" onClick={() => setOpenRev(open ? 0 : r.revision)}>
                <span className={`rev-num ${r.revision === data.policyRevision ? "rev-current" : ""}`}>{r.revision}</span>
                <span className="rev-meta">
                  <span className="rev-title">
                    <Ident value={r.title} kind="text" />
                  </span>
                  <span className="muted small">
                    <Ident value={r.author} /> · {ago(r.createdAt)} · {r.source}
                  </span>
                </span>
                <Badge tone={r.authorizedBy ? AUTH[r.authorizedBy]![0] : "amber"}>{r.authorizedBy ? AUTH[r.authorizedBy]![1] : "authorizer not recorded"}</Badge>
              </button>
              {open && (
                <div className="rev-body">
                  <ul className="rev-changes">
                    {r.changes.map((c) => (
                      <li key={c.rule}>
                        <Badge tone={c.broadening ? "amber" : "neutral"}>{c.kind}</Badge>
                        <span className="mono small">{c.rule}</span>
                        <span className="muted small">{c.detail}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="deploy">
                    <div className="deploy-head small muted">
                      {STATES.map((s) => (
                        <span key={s}>{s}</span>
                      ))}
                    </div>
                    {r.devices.map((d) => {
                      const dev = data.devices.find((x) => x.id === d.deviceId);
                      return (
                        <button type="button" key={d.deviceId} className="deploy-row" onClick={() => go(`devices/${d.deviceId}`)}>
                          <span className="deploy-name">{dev?.name ?? d.deviceId}</span>
                          <span className="deploy-track">
                            {STATES.map((s) => {
                              const hit = d.states.find((x) => x.state === s);
                              return <span key={s} title={hit?.detail ?? s} className={`deploy-cell ${hit ? "on" : ""} ${hit?.detail ? "note" : ""}`} />;
                            })}
                          </span>
                        </button>
                      );
                    })}
                    <div className="small muted">“Applied” is the endpoint's own receipt. “Verified” needs an independent check and stays empty until one runs.</div>
                  </div>
                  {r.platformNotes.length > 0 && (
                    <ul className="platform-notes small">
                      {r.platformNotes.map((n) => (
                        <li key={n.platform}>
                          <strong>{n.platform}</strong> <span className="muted">{n.note}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {r.revision !== data.policyRevision && (
                    <>
                      <button type="button" className="btn btn-quiet" disabled={!canAct.ok} onClick={async () => setProposal(await rollback(r.revision))}>
                        <Icon name="undo" size={15} /> Prepare rollback to this
                      </button>
                      <div className="small muted">{canAct.reason ?? (mode === "demo" ? "Demo: preparing sends nothing." : "Prepares a new proposal; it is signed only after review.")}</div>
                    </>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
