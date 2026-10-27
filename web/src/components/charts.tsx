/**
 * Small, honest charts for the bento cards. Every chart draws only the series it is handed (fields that already exist
 * in the snapshot: hourly flow rollups, device evidence timestamps, revision receipts, app counts). None of them
 * interpolates, smooths into invented points or fills a gap with a guess; an empty series renders nothing and the
 * caller shows an empty state instead.
 */
import type { ReactNode } from "react";
import { useStore } from "../data/store";
import type { TimelinePoint } from "../data/types";
import { Icon, type IconName } from "./ui";

/** Shown on chart cards in demo mode, next to the global "Sample data" banner. */
export function SampleTag() {
  const { mode } = useStore();
  return mode === "demo" ? <span className="sample-tag">Sample data</span> : null;
}

export function Spark({ values, width = 84, height = 32, label }: { values: number[]; width?: number; height?: number; label: string }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1);
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)] as const);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  return (
    <svg className="spark" width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <path className="spark-area" d={`${line} L${width} ${height} L0 ${height} Z`} />
      <path className="spark-line" d={line} />
    </svg>
  );
}

/** A progress ring for a real fraction (n of total). `total` 0 draws an empty track. */
export function Ring({ value, total, size = 64, stroke = 7, label, children }: { value: number; total: number; size?: number; stroke?: number; label: string; children?: ReactNode }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const f = total > 0 ? Math.min(1, Math.max(0, value / total)) : 0;
  return (
    <svg className="ring" width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label}>
      <circle className="ring-track" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} />
      {f > 0 && <circle className="ring-fill" cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} strokeDasharray={c} strokeDashoffset={c * (1 - f)} transform={`rotate(-90 ${size / 2} ${size / 2})`} />}
      {children}
    </svg>
  );
}

export function Kpi({ label, icon, tone, value, unit, sub, chart }: { label: string; icon: IconName; tone?: string; value: ReactNode; unit?: string; sub?: ReactNode; chart?: ReactNode }) {
  return (
    <div className={`kpi ${tone ? `tone-${tone}` : ""}`}>
      <span className="kpi-label">
        <Icon name={icon} size={13} />
        {label}
      </span>
      <div className="kpi-value">
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {sub && <div className="kpi-sub">{sub}</div>}
      {chart && <div className="kpi-chart">{chart}</div>}
    </div>
  );
}

function hourLabel(iso: string) {
  const d = new Date(iso);
  return Number.isFinite(d.getTime()) ? `${String(d.getHours()).padStart(2, "0")}:00` : "";
}

/** Stacked hourly bars: allowed, observed (permitted, not enforced) and blocked, exactly as rolled up. */
export function BarStrip({ points }: { points: TimelinePoint[] }) {
  if (!points.length) return null;
  const H = 112;
  const max = Math.max(...points.map((p) => p.allowed + p.observed + p.blocked), 1);
  const w = 100 / points.length;
  const bw = w * 0.56;
  return (
    <>
      <svg className="strip" viewBox={`0 0 100 ${H}`} preserveAspectRatio="none" role="img" aria-label={`Flows per hour by verdict, ${points.length} hours`}>
        {points.map((p, i) => {
          const x = i * w + (w - bw) / 2;
          const hA = (p.allowed / max) * (H - 2);
          const hO = (p.observed / max) * (H - 2);
          const hB = (p.blocked / max) * (H - 2);
          let y = H;
          const seg = (h: number, cls: string) => {
            if (h <= 0) return null;
            y -= h;
            return <rect key={cls} x={x} y={y} width={bw} height={Math.max(h - 0.6, 0.4)} rx={0.6} className={cls} />;
          };
          return (
            <g key={p.hour}>
              <title>{`${hourLabel(p.hour)}: ${p.allowed} allowed, ${p.observed} observed, ${p.blocked} blocked`}</title>
              {seg(hA, "strip-allowed")}
              {seg(hO, "strip-observed")}
              {seg(Math.max(hB, p.blocked > 0 ? 1.4 : 0), "strip-blocked")}
            </g>
          );
        })}
      </svg>
      <div className="strip-axis" aria-hidden>
        <span>{hourLabel(points[0]!.hour)}</span>
        <span>{hourLabel(points[Math.floor(points.length / 2)]!.hour)}</span>
        <span>{hourLabel(points[points.length - 1]!.hour)}</span>
      </div>
    </>
  );
}

/** Rows × buckets of hourly rollups. Each row is scaled to its own peak, so the grid shows when, not how much. */
export function HeatGrid({ points, bucketHours = 4 }: { points: TimelinePoint[]; bucketHours?: number }) {
  if (!points.length) return null;
  const buckets: TimelinePoint[][] = [];
  for (let i = 0; i < points.length; i += bucketHours) buckets.push(points.slice(i, i + bucketHours));
  const rows: { key: "allowed" | "observed" | "blocked"; label: string; tone: string }[] = [
    { key: "allowed", label: "Allowed", tone: "allowed" },
    { key: "observed", label: "Observed", tone: "observed" },
    { key: "blocked", label: "Blocked", tone: "blocked" },
  ];
  return (
    <>
      <div className="heat" style={{ ["--cols" as string]: buckets.length }} role="table" aria-label={`Flows by verdict in ${bucketHours}-hour buckets`}>
        <span role="columnheader" />
        {buckets.map((b) => (
          <span key={b[0]!.hour} className="heat-col-label" role="columnheader">
            {hourLabel(b[0]!.hour)}
          </span>
        ))}
        {rows.map((r) => {
          const sums = buckets.map((b) => b.reduce((s, p) => s + p[r.key], 0));
          const peak = Math.max(...sums, 1);
          return [
            <span key={r.key} className={`heat-row-label tone-${r.tone}`} role="rowheader">
              <span className="sw" aria-hidden />
              {r.label}
            </span>,
            ...sums.map((v, i) => (
              <span key={`${r.key}${i}`} className={`heat-cell tone-${r.tone}`} role="cell" title={`${r.label} ${v}`} aria-label={`${r.label}, from ${hourLabel(buckets[i]![0]!.hour)}: ${v}`} style={{ ["--lvl" as string]: `${v ? Math.round(14 + (v / peak) * 70) : 0}%` }} />
            )),
          ];
        })}
      </div>
      <div className="heat-scale" aria-hidden>
        <span>fewer</span>
        {[0, 20, 40, 62, 84].map((l) => (
          <i key={l} style={{ ["--lvl" as string]: `${l}%` }} />
        ))}
        <span>more (per row)</span>
      </div>
    </>
  );
}

/** One hexagon per hour of blocked attempts, oldest top left, the current hour outlined. */
export function HexMap({ points }: { points: TimelinePoint[] }) {
  if (!points.length) return null;
  const cols = 6;
  const R = 20;
  const hw = Math.sqrt(3) * R;
  const rows = Math.ceil(points.length / cols);
  const W = cols * hw + hw / 2 + 4;
  const H = rows * R * 1.5 + R / 2 + 4;
  const max = Math.max(...points.map((p) => p.blocked), 1);
  const hex = (cx: number, cy: number) =>
    Array.from({ length: 6 }, (_, k) => {
      const a = (Math.PI / 3) * k - Math.PI / 6;
      return `${(cx + (R - 1) * Math.cos(a)).toFixed(1)},${(cy + (R - 1) * Math.sin(a)).toFixed(1)}`;
    }).join(" ");
  return (
    <svg className="hexmap" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Blocked attempts per hour, ${points.length} hours`}>
      {points.map((p, i) => {
        const row = Math.floor(i / cols);
        const col = i % cols;
        const cx = 2 + hw / 2 + col * hw + (row % 2 ? hw / 2 : 0);
        const cy = 2 + R + row * R * 1.5;
        const lvl = p.blocked ? 18 + Math.round((p.blocked / max) * 72) : 0;
        return (
          <polygon key={p.hour} points={hex(cx, cy)} className={`hex ${i === points.length - 1 ? "hex-now" : ""}`} style={{ fill: `color-mix(in srgb, var(--chart-3) ${lvl}%, color-mix(in srgb, var(--chart-1) ${lvl ? 30 : 0}%, var(--surface-3)))` }}>
            <title>{`${hourLabel(p.hour)}: ${p.blocked} blocked`}</title>
          </polygon>
        );
      })}
    </svg>
  );
}
