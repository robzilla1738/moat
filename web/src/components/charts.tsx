/**
 * The two charts Moat keeps, because each answers its view's question (docs/design.md, "Each view's job"):
 *
 *  - Ring: "how many of my devices are protected?" (Overview) and "is my latest rule change in force?" (Overview).
 *  - BarStrip: "is anything getting through unchecked?" (Overview): connections per hour, blocked / allowed / watched
 *    only, exactly as the devices rolled them up.
 *
 * Every chart draws only the series it is handed. None interpolates or fills a gap with a guess; an empty series
 * renders nothing and the caller shows an empty state instead.
 */
import type { ReactNode } from "react";
import { useStore } from "../data/store";
import type { TimelinePoint } from "../data/types";
import { StatusChip } from "./ui";

/** Shown on chart cards in demo mode, next to the global "Sample data" banner. */
export function SampleTag() {
  const { mode } = useStore();
  return mode === "demo" ? (
    <StatusChip tone="blue" icon="info">
      Sample data
    </StatusChip>
  ) : null;
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

function hourLabel(iso: string) {
  const d = new Date(iso);
  return Number.isFinite(d.getTime()) ? `${String(d.getHours()).padStart(2, "0")}:00` : "";
}

/** Stacked hourly bars: allowed, watched only and blocked, exactly as rolled up. */
export function BarStrip({ points }: { points: TimelinePoint[] }) {
  if (!points.length) return null;
  const H = 96;
  const max = Math.max(...points.map((p) => p.allowed + p.observed + p.blocked), 1);
  const w = 100 / points.length;
  const bw = w * 0.56;
  return (
    <>
      <svg className="strip" viewBox={`0 0 100 ${H}`} preserveAspectRatio="none" role="img" aria-label={`Connections per hour over the last ${points.length} hours: allowed, watched only and blocked`}>
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
              <title>{`${hourLabel(p.hour)}: ${p.allowed} allowed, ${p.observed} watched only, ${p.blocked} blocked`}</title>
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
