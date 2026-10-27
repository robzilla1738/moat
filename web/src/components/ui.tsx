import type { ReactNode } from "react";
import { inspectIdent } from "../data/ident";
import type { ActionState, ChainNode, Coverage, Device, Support, TimelinePoint } from "../data/types";
import { COVERAGE, SUPPORT } from "../format";

type IconName = "home" | "activity" | "sessions" | "rules" | "devices" | "apps" | "coverage" | "shield" | "check" | "x" | "chevron" | "laptop" | "server" | "phone" | "tv" | "linux" | "clock" | "bolt" | "globe" | "lock" | "sun" | "moon" | "undo" | "spark" | "alert" | "dot" | "branch";

const paths: Record<IconName, ReactNode> = {
  home: <path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" />,
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  sessions: <><rect x="3" y="4" width="18" height="14" rx="2.5" /><path d="m7 9 3 2.5L7 14M12 14h5" /></>,
  rules: <><path d="M8 6h13M8 12h13M8 18h13" /><circle cx="4" cy="6" r="1" /><circle cx="4" cy="12" r="1" /><circle cx="4" cy="18" r="1" /></>,
  devices: <><rect x="2" y="5" width="14" height="10" rx="1.5" /><path d="M1 18h16" /><rect x="18" y="8" width="5" height="11" rx="1.2" /></>,
  apps: <><rect x="3" y="3" width="7.5" height="7.5" rx="2" /><rect x="13.5" y="3" width="7.5" height="7.5" rx="2" /><rect x="3" y="13.5" width="7.5" height="7.5" rx="2" /><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="2" /></>,
  coverage: <><path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z" /><path d="m9 12 2 2 4-4" /></>,
  shield: <path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  chevron: <path d="m9 6 6 6-6 6" />,
  laptop: <><rect x="4" y="5" width="16" height="11" rx="1.5" /><path d="M2 19h20" /></>,
  server: <><rect x="4" y="4" width="16" height="7" rx="1.5" /><rect x="4" y="13" width="16" height="7" rx="1.5" /><path d="M8 7.5h.01M8 16.5h.01" /></>,
  phone: <><rect x="7" y="2.5" width="10" height="19" rx="2.5" /><path d="M11 18.5h2" /></>,
  tv: <><rect x="2.5" y="5" width="19" height="12" rx="1.5" /><path d="M8 21h8" /></>,
  linux: <><path d="M12 3c-2.2 0-3.5 1.9-3.5 4.4 0 1.5.4 2.6-.6 4.1C6.6 13.4 5 15.6 5 18c0 1.7 1.6 3 3.5 3h7c1.9 0 3.5-1.3 3.5-3 0-2.4-1.6-4.6-2.9-6.5-1-1.5-.6-2.6-.6-4.1C15.5 4.9 14.2 3 12 3z" /><path d="M10 8h.01M14 8h.01" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  bolt: <path d="M13 2 4 14h7l-1 8 9-12h-7z" />,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" /></>,
  lock: <><rect x="5" y="10.5" width="14" height="10" rx="2" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z" />,
  undo: <><path d="M9 14 4 9l5-5" /><path d="M4 9h10a6 6 0 0 1 0 12h-3" /></>,
  spark: <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6" />,
  alert: <><path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17h.01" /></>,
  dot: <circle cx="12" cy="12" r="4" />,
  branch: <><circle cx="6" cy="5" r="2" /><circle cx="6" cy="19" r="2" /><circle cx="18" cy="12" r="2" /><path d="M6 7v10M6 12h6a4 4 0 0 0 4-4V7" /></>,
};

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {paths[name]}
    </svg>
  );
}
export type { IconName };

export function Badge({ tone = "neutral", children, dot }: { tone?: string; children: ReactNode; dot?: boolean }) {
  return (
    <span className={`badge tone-${tone}`}>
      {dot && <span className="badge-dot" />}
      {children}
    </span>
  );
}

export function CoverageBadge({ c }: { c: Coverage }) {
  return (
    <Badge tone={COVERAGE[c].tone} dot>
      {COVERAGE[c].label}
    </Badge>
  );
}

export function SupportBadge({ s }: { s: Support }) {
  return <Badge tone={SUPPORT[s].tone}>{SUPPORT[s].label}</Badge>;
}

export function Card({ children, className = "", onClick, as }: { children: ReactNode; className?: string; onClick?: () => void; as?: "button" }) {
  if (as === "button")
    return (
      <button type="button" className={`card card-button ${className}`} onClick={onClick}>
        {children}
      </button>
    );
  return <section className={`card ${className}`}>{children}</section>;
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="section-title">
      <h2>{children}</h2>
      {action}
    </div>
  );
}

export function DeviceIcon({ d, size = 18 }: { d: Pick<Device, "platform" | "isController" | "model">; size?: number }) {
  const name: IconName = d.platform === "ios" ? "phone" : d.platform === "android-tv" ? "tv" : d.platform === "linux" ? "linux" : d.isController ? "server" : "laptop";
  return <Icon name={name} size={size} />;
}

export function Chain({ nodes, complete = true, compact = false }: { nodes: ChainNode[]; complete?: boolean; compact?: boolean }) {
  if (compact)
    return (
      <span className="chain-inline">
        {nodes.map((n, i) => (
          <span key={i} className="chain-inline-node">
            {i > 0 && <span className="chain-arrow">→</span>}
            <Ident value={n.name} />
          </span>
        ))}
        {!complete && <span className="muted"> (ancestry incomplete)</span>}
      </span>
    );
  return (
    <ol className="chain">
      {nodes.map((n, i) => (
        <li key={i} className={`chain-node ${i === nodes.length - 1 ? "chain-last" : ""}`}>
          <span className="chain-rail" aria-hidden>
            <span className="chain-dot" />
          </span>
          <div className="chain-body">
            <div className="chain-name">
              <Ident value={n.name} />
              {n.note && <span className="chain-note">{n.note}</span>}
            </div>
            <div className="chain-exe mono">
              <Ident value={n.exe} />
              {n.pid ? <span className="muted"> · pid {n.pid}</span> : null}
            </div>
          </div>
        </li>
      ))}
      {!complete && <li className="chain-gap">Earlier ancestry not observed</li>}
    </ol>
  );
}

export function Steps({ action }: { action: ActionState }) {
  return (
    <ol className="steps" aria-label="Action progress">
      {action.steps.map((s, i) => (
        <li key={i} className={`step step-${s.state}`}>
          <span className="step-mark">{s.state === "done" ? <Icon name="check" size={12} /> : s.state === "failed" ? <Icon name="x" size={12} /> : null}</span>
          <span className="step-text">
            {s.label}
            {s.detail && <span className="step-detail">{s.detail}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function Bars({ points, height = 64 }: { points: TimelinePoint[]; height?: number }) {
  if (!points.length) return <div className="empty-chart">No flow history yet</div>;
  const max = Math.max(...points.map((p) => p.blocked)) || 1;
  const w = 100 / points.length;
  return (
    <svg className="bars" viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" role="img" aria-label="Blocked attempts per hour, last 24 hours">
      {points.map((p, i) => {
        const h = Math.max(1.5, (p.blocked / max) * (height - 4));
        return <rect key={i} x={i * w + w * 0.18} y={height - h} width={w * 0.64} height={h} rx={0.8} className={i === points.length - 1 ? "bar bar-now" : "bar"} />;
      })}
    </svg>
  );
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Row({ children, onClick, chevron }: { children: ReactNode; onClick?: () => void; chevron?: boolean }) {
  const inner = (
    <>
      <div className="row-main">{children}</div>
      {chevron && <Icon name="chevron" size={16} className="row-chevron" />}
    </>
  );
  return onClick ? (
    <button type="button" className="row row-button" onClick={onClick}>
      {inner}
    </button>
  ) : (
    <div className="row">{inner}</div>
  );
}

export function Empty({ title, icon = "check", children }: { title: string; icon?: IconName; children?: ReactNode }) {
  return (
    <div className="empty" role="status">
      <span className="empty-icon" aria-hidden>
        <Icon name={icon} size={20} />
      </span>
      <div className="empty-title">{title}</div>
      {children && <div className="empty-sub">{children}</div>}
    </div>
  );
}

export function SubNav({ active }: { active: "devices" | "coverage" | "diagnostics" | "changed" }) {
  const items = [
    ["devices", "Devices"],
    ["coverage", "Coverage & recovery"],
    ["diagnostics", "Diagnostics"],
    ["changed", "What changed?"],
  ] as const;
  return (
    <nav className="subnav" aria-label="Coverage and recovery">
      {items.map(([k, label]) => (
        <a key={k} href={`#/${k}`} className={active === k ? "active" : ""}>
          {label}
        </a>
      ))}
    </nav>
  );
}

/**
 * Untrusted identifiers (hostnames, app names, session ids, agent text). Hidden characters are shown as escapes,
 * and look-alike or altered values carry a visible warning. The raw value is available on hover for copying.
 */
export function Ident({ value, kind = "id", mono = false, className = "" }: { value: unknown; kind?: "host" | "text" | "id"; mono?: boolean; className?: string }) {
  const r = inspectIdent(value, { kind });
  return (
    <span className={`ident ${mono ? "mono" : ""} ${className}`} title={r.altered || r.warnings.length ? `${String(value ?? "")}${r.warnings.length ? `\n⚠ ${r.warnings.join("; ")}` : ""}` : undefined}>
      {r.text}
      {r.warnings.length > 0 && (
        <span className="ident-warn" role="note" aria-label={`Caution: ${r.warnings.join("; ")}`}>
          <Icon name="alert" size={12} /> {r.warnings[0]}
        </span>
      )}
    </span>
  );
}
