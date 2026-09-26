import { OctagonX, ShieldAlert, ShieldCheck, ShieldHalf, Siren } from "lucide-react";
import type { SafetyIndicator } from "../api/types";
import { INDICATOR_STYLE } from "../lib/safety";
import { cx } from "./ui";

const ICON: Record<SafetyIndicator, typeof ShieldCheck> = {
  ACTIVE: ShieldHalf,
  "READ ONLY": ShieldCheck,
  "SAFE MODE": ShieldAlert,
  STOPPED: OctagonX,
  EMERGENCY: Siren,
};

/** §43: always shows whether state-changing operations are enabled. */
export function SafetyIndicatorBadge({ indicator, compact }: { indicator: SafetyIndicator | null; compact?: boolean }) {
  if (!indicator) {
    return <div className="rounded-lg bg-slate-800 px-3 py-2 text-xs text-slate-400">NETWORK SAFETY · …</div>;
  }
  const style = INDICATOR_STYLE[indicator];
  const Icon = ICON[indicator];
  return (
    <div className={cx("rounded-lg", compact ? "whitespace-nowrap px-2 py-1" : "px-3 py-2", style.className)} title={style.description} role="status" aria-label={`Network safety: ${indicator}`} data-testid="safety-indicator">
      {!compact && <div className="text-[10px] font-semibold uppercase tracking-widest opacity-80">Network safety</div>}
      <div className={cx("flex items-center gap-1.5 font-bold uppercase", compact ? "text-xs" : "text-sm")}>
        <Icon className="h-4 w-4" />
        {indicator === "SAFE MODE" ? "⚠ " : "● "}
        {indicator}
      </div>
    </div>
  );
}

export function SafetyIndicatorBlock({ indicator }: { indicator: SafetyIndicator }) {
  const style = INDICATOR_STYLE[indicator];
  return (
    <div className="space-y-2">
      <SafetyIndicatorBadge indicator={indicator} />
      <p className="text-sm text-slate-600 dark:text-slate-300">{style.description}</p>
    </div>
  );
}
