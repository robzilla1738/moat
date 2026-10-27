/**
 * Moat's one component set (docs/design.md, "Components"). Every screen is built from these: Page, Card, SectionHeader,
 * Stat, StatusChip, ListRow, Banner, EmptyState, Button and Details, plus the untrusted-text renderer (Ident). Styles
 * live in styles.css and use only the tokens in tokens.css; styles.test.ts fails on anything else.
 */
import type { ReactNode } from "react";
import { inspectIdent } from "../data/ident";
import type { ActionState, ChainNode, Coverage, Device, Support } from "../data/types";
import { COVERAGE, SUPPORT } from "../format";

type IconName = "home" | "activity" | "sessions" | "rules" | "devices" | "apps" | "coverage" | "shield" | "check" | "x" | "chevron" | "laptop" | "server" | "phone" | "tv" | "linux" | "clock" | "bolt" | "globe" | "lock" | "sun" | "moon" | "undo" | "spark" | "alert" | "dot" | "branch" | "eye" | "help" | "minus" | "wrench" | "info" | "grid";

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
  eye: <><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>,
  help: <><circle cx="12" cy="12" r="9" /><path d="M9.6 9.3a2.5 2.5 0 0 1 4.8 1c0 1.7-2.4 2.2-2.4 3.7M12 17h.01" /></>,
  minus: <><circle cx="12" cy="12" r="9" /><path d="M8 12h8" /></>,
  wrench: <path d="M14.7 6.3a4 4 0 0 0-5.4 5.1L3.6 17.1a1.5 1.5 0 0 0 2.1 2.1l5.7-5.7a4 4 0 0 0 5.1-5.4l-2.5 2.5-2.1-.4-.4-2.1z" />,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>,
  grid: <><rect x="3" y="3" width="8" height="8" rx="2" /><rect x="13" y="3" width="8" height="5" rx="2" /><rect x="13" y="10" width="8" height="11" rx="2" /><rect x="3" y="13" width="8" height="8" rx="2" /></>,
  branch: <><circle cx="6" cy="5" r="2" /><circle cx="6" cy="19" r="2" /><circle cx="18" cy="12" r="2" /><path d="M6 7v10M6 12h6a4 4 0 0 0 4-4V7" /></>,
};

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={size <= 12 ? 2.2 : 1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {paths[name]}
    </svg>
  );
}
export type { IconName };

export type Tone = "green" | "red" | "amber" | "blue" | "violet" | "neutral";

/** The icon a status tone carries when no more specific one is given: status is never colour alone. */
export const TONE_ICON: Record<Tone, IconName> = { green: "check", red: "x", amber: "alert", blue: "info", violet: "globe", neutral: "dot" };

// ------------------------------------------------------------------------------------------------------ layout

/** The page frame: optional back link, eyebrow, one title, at most one short lede, then content. */
export function Page({ title, lede, eyebrow, back, nav, wide, titleMono, children }: { title: ReactNode; lede?: ReactNode; eyebrow?: ReactNode; back?: { label: string; to: string }; nav?: ReactNode; wide?: boolean; titleMono?: boolean; children: ReactNode }) {
  return (
    <div className={`page ${wide ? "page-wide" : ""}`}>
      {nav}
      {back && (
        <a className="back" href={`#/${back.to}`}>
          <Icon name="chevron" size={16} className="flip" /> {back.label}
        </a>
      )}
      <header className="page-head">
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1 className={titleMono ? "title-mono" : undefined}>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </header>
      {children}
    </div>
  );
}

/** A card: optional header (title + one quiet action or chip), body. One primary action per card. */
export function Card({ title, action, children, className = "", tone, onClick, id }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; tone?: Tone; onClick?: () => void; id?: string }) {
  const cls = `card ${tone ? `card-${tone}` : ""} ${className}`;
  const body = (
    <>
      {title !== undefined && <SectionHeader title={title} action={action} level={3} />}
      {children}
    </>
  );
  if (onClick)
    return (
      <button type="button" className={`${cls} card-button`} onClick={onClick} id={id}>
        {body}
      </button>
    );
  return (
    <section className={cls} id={id}>
      {body}
    </section>
  );
}

/** Section header: one title, at most one trailing action (a link) or chip. */
export function SectionHeader({ title, action, level = 2 }: { title: ReactNode; action?: ReactNode; level?: 2 | 3 }) {
  const H = level === 2 ? "h2" : "h3";
  return (
    <div className={`section-header section-header-${level}`}>
      <H>{title}</H>
      {action}
    </div>
  );
}

/** A figure with a label. Used where a number answers the view's question; never decorative. */
export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

/** Status chip: icon + label, always. Neutral chips (counts) may omit the icon. */
export function StatusChip({ tone = "neutral", children, icon }: { tone?: Tone; children: ReactNode; icon?: IconName | null }) {
  const name = icon === null ? undefined : icon ?? (tone !== "neutral" ? TONE_ICON[tone] : undefined);
  return (
    <span className={`chip tone-${tone}`}>
      {name && <Icon name={name} size={12} />}
      {children}
    </span>
  );
}

export function CoverageChip({ c }: { c: Coverage }) {
  return (
    <StatusChip tone={COVERAGE[c].tone} icon={COVERAGE[c].icon}>
      {COVERAGE[c].label}
    </StatusChip>
  );
}

export function SupportChip({ s }: { s: Support }) {
  return (
    <StatusChip tone={SUPPORT[s].tone} icon={SUPPORT[s].icon}>
      {SUPPORT[s].label}
    </StatusChip>
  );
}

/** A list row: leading icon, title, one sub line, trailing chip or figure; a row that opens something shows a chevron. */
export function ListRow({ icon, iconTone, title, sub, trailing, onClick, href }: { icon?: ReactNode; iconTone?: Tone; title: ReactNode; sub?: ReactNode; trailing?: ReactNode; onClick?: () => void; href?: string }) {
  const inner = (
    <>
      {icon && <span className={`row-icon ${iconTone ? `tone-${iconTone}` : ""}`}>{icon}</span>}
      <span className="row-main">
        <span className="row-title">{title}</span>
        {sub && <span className="row-sub">{sub}</span>}
      </span>
      {trailing && <span className="row-trailing">{trailing}</span>}
      {(onClick || href) && <Icon name="chevron" size={16} className="row-chevron" />}
    </>
  );
  if (href)
    return (
      <a className="row row-link" href={href}>
        {inner}
      </a>
    );
  if (onClick)
    return (
      <button type="button" className="row row-link" onClick={onClick}>
        {inner}
      </button>
    );
  return <div className="row">{inner}</div>;
}

/** A list of rows inside a card. */
export function List({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <div className="list" role={label ? "list" : undefined} aria-label={label}>
      {children}
    </div>
  );
}

/**
 * Banner: an announcement or warning across the top of a view or a card. Coverage and safety warnings are banners and
 * are never put behind a disclosure; their exact technical reason can be.
 */
export function Banner({ tone = "blue", title, children, action, role }: { tone?: Tone; title: ReactNode; children?: ReactNode; action?: ReactNode; role?: "status" | "alert" | "note" }) {
  return (
    <div className={`banner tone-${tone}`} role={role ?? (tone === "red" || tone === "amber" ? "alert" : "status")}>
      <span className="banner-icon" aria-hidden>
        <Icon name={tone === "blue" ? "info" : TONE_ICON[tone]} size={16} />
      </span>
      <div className="banner-body">
        <strong className="banner-title">{title}</strong>
        {children && <span className="banner-text"> {children}</span>}
      </div>
      {action && <div className="banner-action">{action}</div>}
    </div>
  );
}

/** Empty state: what this view will show and, when there is one, the next step. */
export function EmptyState({ title, icon = "check", children, action }: { title: string; icon?: IconName; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty" role="status">
      <span className="empty-icon" aria-hidden>
        <Icon name={icon} size={20} />
      </span>
      <div className="empty-title">{title}</div>
      {children && <div className="empty-text">{children}</div>}
      {action}
    </div>
  );
}

type ButtonKind = "primary" | "secondary" | "quiet" | "danger";
/** Buttons: one primary per card; secondary for the alternative; quiet for everything else. Labels say what happens. */
export function Button({ kind = "secondary", children, icon, onClick, disabled, describedBy, type = "button", href }: { kind?: ButtonKind; children: ReactNode; icon?: IconName; onClick?: () => void; disabled?: boolean; describedBy?: string; type?: "button" | "submit"; href?: string }) {
  const content = (
    <>
      {icon && <Icon name={icon} size={16} />}
      {children}
    </>
  );
  if (href)
    return (
      <a className={`btn btn-${kind}`} href={href}>
        {content}
      </a>
    );
  return (
    <button type={type} className={`btn btn-${kind}`} onClick={onClick} disabled={disabled} aria-describedby={describedBy}>
      {content}
    </button>
  );
}

export function Actions({ children }: { children: ReactNode }) {
  return <div className="actions">{children}</div>;
}

/** Fine print under an action: what exactly will happen. One or two short sentences. */
export function Fine({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <p className="fine" id={id}>
      {children}
    </p>
  );
}

/**
 * Disclosure for secondary and technical detail (hostnames, ports, hashes, rule versions, signer and task ids). Never
 * for a warning about coverage or safety: those stay visible as a Banner or a chip.
 */
export function Details({ summary = "Details", children, open }: { summary?: ReactNode; children: ReactNode; open?: boolean }) {
  return (
    <details className="details" open={open}>
      <summary>
        <Icon name="chevron" size={14} className="details-chevron" />
        {summary}
      </summary>
      <div className="details-body">{children}</div>
    </details>
  );
}

/** Label / value pairs (inside Details or a technical page). */
export function Facts({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="facts">
      {rows.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Secondary navigation between related views (tabs). */
export function SubNav({ items, active, label }: { items: [string, string][]; active: string; label: string }) {
  return (
    <nav className="subnav" aria-label={label}>
      {items.map(([k, text]) => (
        <a key={k} href={`#/${k}`} className={active === k ? "active" : ""} aria-current={active === k ? "page" : undefined}>
          {text}
        </a>
      ))}
    </nav>
  );
}

export const DEVICE_NAV: [string, string][] = [
  ["devices", "Devices"],
  ["coverage", "Coverage & recovery"],
  ["changed", "What changed?"],
];
export const RULES_NAV: [string, string][] = [
  ["rules", "Rules"],
  ["learning", "Learn"],
  ["learning/packs", "Rule packs"],
];

export function DeviceIcon({ d, size = 18 }: { d: Pick<Device, "platform" | "isController" | "model">; size?: number }) {
  const name: IconName = d.platform === "ios" || d.platform === "dns-client" ? "phone" : d.platform === "android-tv" ? "tv" : d.platform === "linux" ? "linux" : d.isController ? "server" : "laptop";
  return <Icon name={name} size={size} />;
}

/** A process chain: compact ("Claude Code → zsh → curl") or the full list with file paths (for Details). */
export function Chain({ nodes, complete = true, compact = false }: { nodes: ChainNode[]; complete?: boolean; compact?: boolean }) {
  if (compact)
    return (
      <span className="chain-inline">
        {nodes.map((n, i) => (
          <span key={i}>
            {i > 0 && <span className="chain-arrow"> → </span>}
            <Ident value={n.name} />
          </span>
        ))}
        {!complete && <span className="muted"> (earlier steps not seen)</span>}
      </span>
    );
  return (
    <ol className="chain">
      {nodes.map((n, i) => (
        <li key={i}>
          <span className="chain-name">
            <Ident value={n.name} />
            {n.note && <span className="muted"> · {n.note}</span>}
          </span>
          <span className="chain-exe">
            <Ident value={n.exe} mono />
            {n.pid ? <span className="muted"> · pid {n.pid}</span> : null}
          </span>
        </li>
      ))}
      {!complete && <li className="muted">Earlier steps were not seen</li>}
    </ol>
  );
}

/** Progress of an owner action, step by step, from evidence only. */
export function Steps({ action }: { action: ActionState }) {
  return (
    <ol className="steps" aria-label="Progress">
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

/**
 * Untrusted identifiers (hostnames, app names, task ids, agent text). Hidden characters are shown as escapes, and
 * look-alike or altered values carry a visible warning (never hidden behind a disclosure). The raw value is available
 * on hover for copying.
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
