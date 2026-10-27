/**
 * Rules: "What are my rules, and is my latest change in force everywhere?" A prepared change waiting to be signed
 * comes first, then a change being tried out, temporary permissions, and the list of rule changes (newest open).
 */
import { useState } from "react";
import { Actions, Banner, Button, Card, Details, EmptyState, Facts, Fine, Icon, Ident, List, ListRow, Page, Stat, StatusChip, SubNav, RULES_NAV, type Tone } from "../components/ui";
import type { WireProposal } from "../data/api";
import { useData, useStore } from "../data/store";
import type { RevisionState } from "../data/types";
import { ago, until } from "../format";

const STATES: [RevisionState, string][] = [
  ["approved", "Approved"],
  ["distributed", "Sent"],
  ["received", "Received"],
  ["applied", "Applied"],
  ["verified", "Checked"],
];

const AUTH: Record<string, [Tone, string]> = { owner_key: ["blue", "Owner key"], narrowing: ["neutral", "Only narrows"], temporary_grant_overlay: ["green", "One-time permission"], delegated_issuer: ["green", "Approval key"] };

/** A prepared change (going back, an approved list, or rule packs). Allowing more needs an owner-key signature made off this page. */
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
        setErr(`Paste exactly what the command printed (${(e as Error).message}).`);
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
    <Card className="proposal" title="Prepared, not signed" action={<StatusChip tone={p.broadening ? "amber" : "neutral"}>{p.broadening ? "Allows more" : "Only narrows"}</StatusChip>}>
      <p>
        {p.rollback_of != null ? <>This brings back version {p.rollback_of}&apos;s rules as a new change.</> : <Ident value={p.message} kind="text" />} Nothing changes on any device until it&apos;s signed and each device confirms it.
      </p>
      {p.broadening ? (
        <>
          <p className="muted">Because it allows more, it needs your owner key. Your owner key never goes in a browser: on the computer that holds it, run this and paste what it prints.</p>
          <pre className="code">{`moat-controller owner-authorize <owner.key> ${p.authorization_subject} ${p.authorization_digest}`}</pre>
          <label htmlFor={`auth-${p.id}`}>Paste what it printed</label>
          <textarea id={`auth-${p.id}`} className="input mono" rows={3} value={auth} onChange={(e) => setAuth(e.target.value)} spellCheck={false} />
        </>
      ) : (
        <p className="muted">Changes that only narrow access are signed without your owner key.</p>
      )}
      {err && <p className="error">{err}</p>}
      <Actions>
        <Button kind="primary" disabled={!canAct.ok || busy || (p.broadening && !auth.trim())} onClick={submit}>
          {busy ? "Signing…" : "Sign and send to devices"}
        </Button>
        <Button kind="quiet" onClick={onDone}>
          Close
        </Button>
      </Actions>
      {canAct.reason && <Fine>{canAct.reason}</Fine>}
      <Details summary="Technical details">
        <Facts
          rows={[
            ["Proposal", <Ident key="i" value={p.id} mono />],
            ["Builds on version", String(p.base_revision)],
          ]}
        />
      </Details>
    </Card>
  );
}

export function Rules({ go }: { go: (to: string) => void }) {
  const data = useData();
  const { rollback, canAct, mode } = useStore();
  const [proposal, setProposal] = useState<WireProposal | null>(null);
  const sim = data.simulation;
  return (
    <Page title="Rules" lede="Your rules decide what each app may connect to. Changes that allow more need your owner key; an agent can suggest a change but never approve one." nav={<SubNav items={RULES_NAV} active="rules" label="Rules" />}>
      {proposal && <ProposalPanel p={proposal} onDone={() => setProposal(null)} />}

      {sim && (
        <Card title="Try a change before you sign it" action={<StatusChip tone="amber">Not signed</StatusChip>}>
          <p className="claim">
            <Ident value={sim.title} kind="text" />
          </p>
          <div className="stats">
            <Stat label="Would be blocked" value={sim.newlyBlocked} tone={sim.newlyBlocked ? "red" : undefined} />
            <Stat label="Would be allowed" value={sim.newlyAllowed} tone={sim.newlyAllowed ? "amber" : undefined} />
            <Stat label="Connections checked" value={sim.observations.toLocaleString()} sub="from recent history" />
          </div>
          {sim.platforms.some((p) => !p.compiles) && (
            <Banner tone="amber" title="Won't apply everywhere.">
              <Ident
                value={sim.platforms
                  .filter((p) => !p.compiles)
                  .map((p) => `${p.adapter}: ${p.note}`)
                  .join(" · ")}
                kind="text"
              />
            </Banner>
          )}
          <Details summary={`What would change (${sim.changed.length})`}>
            <List>
              {sim.changed.map((c, k) => (
                <ListRow key={k} title={<Ident value={c.destination} kind="host" mono />} sub={<><Ident value={c.app} /> · <Ident value={c.device} /></>} trailing={<span>{c.before} → <strong className="tone-red">{c.after}</strong></span>} />
              ))}
            </List>
            {sim.unobserved.length > 0 && <Fine>Never seen in history: {sim.unobserved.join(", ")}</Fine>}
            {sim.unacknowledged.length > 0 && <Fine>Not using your current rules yet: {sim.unacknowledged.join(", ")}</Fine>}
            <Fine>
              Works on: {sim.platforms.map((p) => `${p.adapter} ${p.compiles ? "✓" : "✕"}`).join(" · ")}
            </Fine>
          </Details>
          <Fine>
            <Ident value={sim.disclaimer} kind="text" />
          </Fine>
        </Card>
      )}

      {data.grants.length > 0 && (
        <Card title="Temporary permissions">
          <List>
            {data.grants.map((g) => (
              <ListRow key={g.id} icon={<Icon name="clock" size={16} />} title={<Ident value={g.destination} kind="host" mono />} sub={<>by <Ident value={g.by} /> · <Ident value={g.scope} kind="text" /></>} trailing={<StatusChip tone="green">{until(g.expiresAt)}</StatusChip>} />
            ))}
          </List>
        </Card>
      )}

      <Card title="Rule changes">
        {data.revisions.length === 0 && (
          <EmptyState title="No rules signed yet" icon="rules">
            Write rules in your rules folder and sign them with your owner key; each change appears here with where it&apos;s in force.
          </EmptyState>
        )}
        {data.revisions.map((r, idx) => (
          <details key={r.revision} className="details revision" open={idx === 0}>
            <summary>
              <Icon name="chevron" size={14} className="details-chevron" />
              <span className={`rev-num ${r.revision === data.policyRevision ? "rev-current" : ""}`} aria-label={`version ${r.revision}`}>
                {r.revision}
              </span>
              <span className="row-main">
                <span className="row-title">
                  <Ident value={r.title} kind="text" />
                </span>
                <span className="row-sub">
                  <Ident value={r.author} /> · {ago(r.createdAt)}
                  {r.revision === data.policyRevision ? " · current" : ""}
                </span>
              </span>
              <StatusChip tone={r.authorizedBy ? AUTH[r.authorizedBy]![0] : "amber"}>{r.authorizedBy ? AUTH[r.authorizedBy]![1] : "Signer not recorded"}</StatusChip>
            </summary>
            <div className="details-body details-plain">
              <List>
                {r.changes.map((c) => (
                  <ListRow key={c.rule} title={<><StatusChip tone={c.broadening ? "amber" : "neutral"}>{c.kind}</StatusChip> <Ident value={c.rule} mono /></>} sub={<Ident value={c.detail} kind="text" />} />
                ))}
              </List>
              <div className="deploy" role="table" aria-label="Where this change is in force">
                <div className="deploy-row deploy-head" role="row">
                  <span role="columnheader">Device</span>
                  {STATES.map(([s, label]) => (
                    <span key={s} role="columnheader">
                      {label}
                    </span>
                  ))}
                </div>
                {r.devices.map((d) => {
                  const dev = data.devices.find((x) => x.id === d.deviceId);
                  return (
                    <button type="button" key={d.deviceId} className="deploy-row" role="row" onClick={() => go(`devices/${encodeURIComponent(d.deviceId)}`)}>
                      <span className="deploy-name" role="cell">
                        <Ident value={dev?.name ?? d.deviceId} />
                      </span>
                      {STATES.map(([s, label]) => {
                        const hit = d.states.find((x) => x.state === s);
                        return <span key={s} role="cell" title={hit?.detail ?? label} aria-label={`${label}: ${hit ? "yes" : "not yet"}`} className={`deploy-cell ${hit ? "on" : ""} ${hit?.detail ? "note" : ""}`} />;
                      })}
                    </button>
                  );
                })}
              </div>
              <Fine>&ldquo;Applied&rdquo; is the device&apos;s own confirmation. &ldquo;Checked&rdquo; needs an independent check and stays empty until one runs.</Fine>
              {r.platformNotes.length > 0 && (
                <List>
                  {r.platformNotes.map((n) => (
                    <ListRow key={n.platform} title={n.platform} sub={<Ident value={n.note} kind="text" />} />
                  ))}
                </List>
              )}
              {r.revision !== data.policyRevision && (
                <>
                  <Actions>
                    <Button icon="undo" disabled={!canAct.ok} onClick={async () => setProposal(await rollback(r.revision))}>
                      Go back to this version
                    </Button>
                  </Actions>
                  <Fine>{canAct.reason ?? (mode === "demo" ? "Demo: nothing is sent." : "Prepares a change for you to review; nothing is signed yet.")}</Fine>
                </>
              )}
            </div>
          </details>
        ))}
      </Card>
    </Page>
  );
}
