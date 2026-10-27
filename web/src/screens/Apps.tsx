import { useState } from "react";
import { Badge, Card, Icon, SubNav } from "../components/ui";
import { useData } from "../data/store";
import { ago } from "../format";

export function Apps({ go: _go }: { go: (to: string) => void }) {
  const data = useData();
  const [q, setQ] = useState("");
  const list = data.apps.filter((a) => (a.name + a.family + a.category).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="page">
      <SubNav active="apps" />
      <div className="page-head">
        <h1>Apps</h1>
        <p className="lede">Application family, actual executable and signer are separate facts. A process named curl is not suspicious by itself; who launched it, under which policy, is what matters.</p>
      </div>
      <label className="search">
        <Icon name="apps" size={16} />
        <input placeholder="Search apps" value={q} onChange={(e) => setQ(e.target.value)} />
      </label>
      <div className="stack">
        {list.map((a) => (
          <Card key={a.id} className="app-card">
            <div className="app-top">
              <div className="app-avatar">{a.name.slice(0, 1)}</div>
              <div className="app-meta">
                <div className="app-name">{a.name}</div>
                <div className="muted small ellipsis">
                  {a.category} · {a.signing}
                </div>
              </div>
              <Badge tone={a.enforcement === "observed" ? "neutral" : a.enforcement === "session-only" ? "green" : "blue"}>{a.enforcement === "observed" ? "observed" : a.enforcement === "session-only" ? "protected when launched" : "enforced"}</Badge>
            </div>
            <div className="app-dests">
              {a.destinations.map((d) => (
                <span key={d.host} className={`chip chip-${d.verdict}`}>
                  <span className="mono">{d.host}</span>
                  <span className="chip-count">{d.count}</span>
                  {d.firstSeen && <span className="chip-new">new</span>}
                </span>
              ))}
            </div>
            <div className="muted small">
              {a.profile} · {a.devices.length} device{a.devices.length > 1 ? "s" : ""} · active {ago(a.lastActive)}
              {a.recognizedBy && ` · recognized by ${a.recognizedBy}`}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
