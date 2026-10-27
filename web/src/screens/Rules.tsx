import { useState } from "react";
import { Badge, Card, Icon, SectionTitle } from "../components/ui";
import { useStore } from "../data/store";
import type { RevisionState } from "../data/types";
import { ago, until } from "../format";

const STATES: RevisionState[] = ["approved", "distributed", "received", "applied", "verified"];

export function Rules({ go }: { go: (to: string) => void }) {
  const { data, rollback } = useStore();
  const [openRev, setOpenRev] = useState<number>(data.revisions[0]?.revision ?? 0);
  const sim = data.simulation;
  return (
    <div className="page">
      <div className="page-head">
        <h1>Rules</h1>
        <p className="lede">Policy lives in Git and is signed by a separate signer. Broadening changes need your owner key; agents can prepare a diff but never authorize one.</p>
      </div>

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

      {data.grants.length > 0 && (
        <>
          <SectionTitle>Temporary grants</SectionTitle>
          <div className="stack">
            {data.grants.map((g) => (
              <Card key={g.id} className="grant">
                <Icon name="clock" size={16} />
                <div>
                  <div className="mono small">{g.destination}</div>
                  <div className="muted small">
                    {g.scope} · by {g.by}
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
                  <span className="rev-title">{r.title}</span>
                  <span className="muted small">
                    {r.author} · {ago(r.createdAt)} · {r.source}
                  </span>
                </span>
                <Badge tone={r.authorizedBy === "owner_key" ? "blue" : r.authorizedBy === "narrowing" ? "neutral" : "green"}>{r.authorizedBy === "owner_key" ? "owner key" : r.authorizedBy === "narrowing" ? "narrowing" : "grant overlay"}</Badge>
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
                    <button type="button" className="btn btn-quiet" onClick={() => rollback(r.revision)}>
                      <Icon name="undo" size={15} /> Roll back to this
                    </button>
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
