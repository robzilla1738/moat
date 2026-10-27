import { useState } from "react";
import { Actions, Button, Card, Details, Facts, Fine, Ident, StatusChip } from "../components/ui";
import { useData, useStore } from "../data/store";
import { until } from "../format";

/**
 * Approve from this browser: it gets its own narrow approval key. Your owner key stays on your own machine; it signs a
 * permission naming the devices, the kind of approval and the longest time this browser may approve for.
 */
export function ApprovalsCard() {
  const { issuer, createIssuer, registerDelegation, forgetIssuer, mode } = useStore();
  const data = useData();
  const [json, setJson] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const devices = data.devices.filter((d) => d.platform === "linux" || d.platform === "macos").map((d) => d.id);
  const d = issuer?.delegation;
  return (
    <Card className="approvals" title="Approve from this browser" action={d ? <StatusChip tone="green">Set up</StatusChip> : <StatusChip>Not set up</StatusChip>}>
      {!issuer && (
        <>
          <p className="muted">Give this phone or browser its own approval key, so you can allow something once without your owner key. It can only approve what your owner key lets it.</p>
          <Actions>
            <Button icon="shield" onClick={createIssuer}>
              Create an approval key for this device
            </Button>
          </Actions>
        </>
      )}
      {issuer && !d && (
        <>
          <p className="muted">
            Key <Ident value={issuer.keyId} mono /> was created in this browser. On the computer that holds your owner key, run this, then paste what it prints:
          </p>
          <pre className="code">{`moat-controller delegate-issuer <owner.key> ${issuer.publicHex} --devices ${devices.join(",") || "<device-id>"} --max-ttl 3600 --days 30 --label phone`}</pre>
          <label htmlFor="delegation">Paste what it printed</label>
          <textarea id="delegation" className="input mono" rows={3} value={json} onChange={(e) => setJson(e.target.value)} spellCheck={false} />
          {err && <p className="error">{err}</p>}
          <Actions>
            <Button
              kind="primary"
              disabled={!json.trim()}
              onClick={async () => {
                setErr(await registerDelegation(json));
              }}
            >
              Use this approval
            </Button>
            <Button kind="quiet" onClick={forgetIssuer}>
              Discard key
            </Button>
          </Actions>
        </>
      )}
      {issuer && d && (
        <>
          <p>
            This browser may approve <strong>{d.scope.kinds.join(", ").replace(/_/g, " ")}</strong> for at most {Math.round(d.scope.max_ttl_seconds / 60)} min at a time, for {until(d.not_after)}.
          </p>
          <Details summary="Technical details">
            <Facts
              rows={[
                ["Key", <Ident key="k" value={issuer.keyId} mono />],
                ["Devices", <Ident key="d" value={d.scope.devices.join(", ")} />],
              ]}
            />
            <Fine>The controller checks this permission and your signature on each exact approval. Anything broader still needs your owner key.</Fine>
          </Details>
          {mode === "demo" && <Fine>Demo: nothing was registered.</Fine>}
          <Actions>
            <Button kind="quiet" onClick={forgetIssuer}>
              Remove from this browser
            </Button>
          </Actions>
        </>
      )}
    </Card>
  );
}
