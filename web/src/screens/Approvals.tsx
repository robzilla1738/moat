import { useState } from "react";
import { Badge, Card, Icon, Ident, SectionTitle } from "../components/ui";
import { useData, useStore } from "../data/store";
import { until } from "../format";

/**
 * Phone approvals: this browser gets its own narrowly delegated key. The owner key stays on the owner's machine;
 * it signs a delegation naming the devices, the kind of approval and the longest lifetime this browser may approve.
 */
export function ApprovalsCard() {
  const { issuer, createIssuer, registerDelegation, forgetIssuer, mode } = useStore();
  const data = useData();
  const [json, setJson] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const devices = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos").map((d) => d.id);
  const d = issuer?.delegation;
  return (
    <Card className="approvals">
      <SectionTitle action={d ? <Badge tone="green">delegated</Badge> : <Badge>not set up</Badge>}>Phone approvals on this device</SectionTitle>
      {!issuer && (
        <>
          <p className="small muted">Give this browser its own approval key. It can only approve what your owner key delegates to it (for example: allow once, on these devices, for at most an hour). The owner key itself never comes here.</p>
          <button type="button" className="btn btn-quiet" onClick={createIssuer}>
            <Icon name="shield" size={15} /> Create an approval key for this device
          </button>
        </>
      )}
      {issuer && !d && (
        <>
          <p className="small muted">
            Key <Ident value={issuer.keyId} mono /> was created in this browser. On the machine that holds your owner key, run:
          </p>
          <pre className="code">{`moat-controller delegate-issuer <owner.key> ${issuer.publicHex} --devices ${devices.join(",") || "<device-id>"} --max-ttl 3600 --days 30 --label phone`}</pre>
          <label className="small" htmlFor="delegation">
            Paste the printed delegation
          </label>
          <textarea id="delegation" className="input mono" rows={3} value={json} onChange={(e) => setJson(e.target.value)} spellCheck={false} />
          {err && <div className="small bad">{err}</div>}
          <div className="decision-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!json.trim()}
              onClick={async () => {
                setErr(await registerDelegation(json));
              }}
            >
              Use this delegation
            </button>
            <button type="button" className="btn btn-quiet" onClick={forgetIssuer}>
              Discard key
            </button>
          </div>
        </>
      )}
      {issuer && d && (
        <>
          <dl className="facts">
            <div>
              <dt>Key</dt>
              <dd>
                <Ident value={issuer.keyId} mono />
              </dd>
            </div>
            <div>
              <dt>May approve</dt>
              <dd>
                {d.scope.kinds.join(", ")} on <Ident value={d.scope.devices.join(", ")} />, at most {Math.round(d.scope.max_ttl_seconds / 60)} min each
              </dd>
            </div>
            <div>
              <dt>Delegation ends</dt>
              <dd>{until(d.not_after)}</dd>
            </div>
          </dl>
          <p className="small muted">The signer checks this delegation and your signature over each exact plan. Broader changes still need your owner key.{mode === "demo" ? " (Demo: nothing was registered.)" : ""}</p>
          <button type="button" className="btn btn-quiet" onClick={forgetIssuer}>
            Remove from this browser
          </button>
        </>
      )}
    </Card>
  );
}
