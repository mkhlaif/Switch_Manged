import { AlertTriangle, Loader2, X } from "lucide-react";
import { useEffect, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { ApiError } from "../api/client";
import type { PortClass, SwitchStatus } from "../api/types";

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ Buttons */
type Variant = "primary" | "secondary" | "danger" | "ghost" | "warning";
const variants: Record<Variant, string> = {
  primary: "bg-teal-700 text-white hover:bg-teal-800 disabled:bg-teal-700/50 dark:bg-teal-600 dark:hover:bg-teal-500",
  secondary:
    "border border-slate-300 bg-white text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800",
  danger: "bg-red-600 text-white hover:bg-red-700 disabled:bg-red-600/50",
  warning: "bg-amber-500 text-slate-950 hover:bg-amber-400 disabled:bg-amber-500/50",
  ghost: "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800",
};

export function Button({
  variant = "secondary",
  size = "md",
  loading,
  icon,
  children,
  className,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md" | "lg"; loading?: boolean; icon?: ReactNode }) {
  const sizes = { sm: "h-8 px-2.5 text-xs", md: "h-9 px-3.5 text-sm", lg: "h-11 px-5 text-base" };
  return (
    <button
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-600 disabled:cursor-not-allowed",
        variants[variant],
        sizes[size],
        className,
      )}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

/* ------------------------------------------------------------------ Layout blocks */
export function Card({ children, className, title, actions, padded = true }: { children: ReactNode; className?: string; title?: ReactNode; actions?: ReactNode; padded?: boolean }) {
  return (
    <section className={cx("rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold tracking-wide text-slate-700 dark:text-slate-200">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={padded ? "p-4" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Field({ label, hint, children, error }: { label: string; hint?: ReactNode; children: ReactNode; error?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</span>
      {children}
      {hint && !error && <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
      {error && <span className="mt-1 block text-xs text-red-600 dark:text-red-400">{error}</span>}
    </label>
  );
}

const inputBase =
  "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-teal-600 focus:outline-none focus:ring-2 focus:ring-teal-600/20 disabled:bg-slate-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:disabled:bg-slate-900";

// An explicit width in className (w-40, w-64, …) replaces the default full width.
function fieldClass(className?: string, extra = "") {
  const base = className && /(^|\s)w-/.test(className) ? inputBase.replace("w-full ", "") : inputBase;
  return cx(base, extra, className);
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={fieldClass(props.className)} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={fieldClass(props.className, "pr-8")} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={fieldClass(props.className)} />;
}

export function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cx(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-50",
        checked ? "bg-teal-600" : "bg-slate-300 dark:bg-slate-700",
      )}
    >
      <span className={cx("inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform", checked ? "translate-x-5" : "translate-x-0.5")} />
    </button>
  );
}

/* ------------------------------------------------------------------ Badges */
type Tone = "green" | "teal" | "amber" | "orange" | "red" | "slate" | "blue" | "violet";
const tones: Record<Tone, string> = {
  green: "bg-emerald-100 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-400/30",
  teal: "bg-teal-100 text-teal-800 ring-teal-600/20 dark:bg-teal-500/15 dark:text-teal-300 dark:ring-teal-400/30",
  amber: "bg-amber-100 text-amber-900 ring-amber-600/25 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
  orange: "bg-orange-100 text-orange-900 ring-orange-600/25 dark:bg-orange-500/15 dark:text-orange-300 dark:ring-orange-400/30",
  red: "bg-red-100 text-red-800 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30",
  slate: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-700/40 dark:text-slate-300 dark:ring-slate-500/30",
  blue: "bg-sky-100 text-sky-800 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300 dark:ring-sky-400/30",
  violet: "bg-violet-100 text-violet-800 ring-violet-600/20 dark:bg-violet-500/15 dark:text-violet-300 dark:ring-violet-400/30",
};

export function Badge({ tone = "slate", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return <span className={cx("inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", tones[tone], className)}>{children}</span>;
}

export const CLASS_LABEL: Record<string, string> = {
  ACCESS: "ACCESS",
  LIKELY_ACCESS: "LIKELY ACCESS",
  UNKNOWN: "UNKNOWN",
  LIKELY_TRUNK: "LIKELY TRUNK",
  TRUNK: "TRUNK",
};
const CLASS_TONE: Record<string, Tone> = {
  ACCESS: "green",
  LIKELY_ACCESS: "teal",
  UNKNOWN: "slate",
  LIKELY_TRUNK: "orange",
  TRUNK: "red",
};

export function ClassBadge({ value, confidence, large }: { value: PortClass | string; confidence?: string; large?: boolean }) {
  if (!value) return <span className="text-slate-400">—</span>;
  return (
    <Badge tone={CLASS_TONE[value] || "slate"} className={large ? "px-2.5 py-1 text-sm" : undefined}>
      {CLASS_LABEL[value] || value}
      {confidence && <span className="font-normal opacity-75">· {confidence}</span>}
    </Badge>
  );
}

const STATUS_STYLE: Record<string, { tone: Tone; label: string; dot: string }> = {
  online: { tone: "green", label: "Online", dot: "bg-emerald-500" },
  offline: { tone: "red", label: "Offline", dot: "bg-red-500" },
  auth_failed: { tone: "red", label: "Auth failed", dot: "bg-red-500" },
  hostkey_error: { tone: "orange", label: "Host key", dot: "bg-orange-500" },
  error: { tone: "amber", label: "Error", dot: "bg-amber-500" },
  unknown: { tone: "slate", label: "Not checked", dot: "bg-slate-400" },
};

export function SwitchStatusBadge({ status }: { status: SwitchStatus | string }) {
  const s = STATUS_STYLE[status] || STATUS_STYLE.unknown;
  return (
    <Badge tone={s.tone}>
      <span className={cx("h-1.5 w-1.5 rounded-full", s.dot)} />
      {s.label}
    </Badge>
  );
}

const RESULT_STYLE: Record<string, { tone: Tone; label: string }> = {
  found: { tone: "green", label: "Found" },
  not_found: { tone: "slate", label: "Not found" },
  timeout: { tone: "amber", label: "Timeout" },
  auth_failed: { tone: "red", label: "Auth failed" },
  hostkey_error: { tone: "orange", label: "Host key" },
  connection_failed: { tone: "red", label: "Connection failed" },
  command_failed: { tone: "orange", label: "Command failed" },
  unsupported: { tone: "violet", label: "No profile" },
  blocked: { tone: "red", label: "Blocked" },
  error: { tone: "red", label: "Error" },
  running: { tone: "blue", label: "Checking…" },
  pending: { tone: "slate", label: "Pending" },
};

export function ResultStatusBadge({ status }: { status: string }) {
  const s = RESULT_STYLE[status] || { tone: "slate" as Tone, label: status };
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

const ACTION_STYLE: Record<string, { tone: Tone; label: string }> = {
  planned: { tone: "slate", label: "Planned" },
  expired: { tone: "slate", label: "Expired" },
  denied: { tone: "violet", label: "Denied" },
  dry_run: { tone: "blue", label: "Dry run" },
  running: { tone: "amber", label: "Running" },
  success: { tone: "green", label: "Success" },
  failed: { tone: "red", label: "Failed" },
  aborted: { tone: "orange", label: "Aborted" },
  interrupted: { tone: "red", label: "Interrupted" },
};

export function ActionStatusBadge({ status }: { status: string }) {
  const s = ACTION_STYLE[status] || { tone: "slate" as Tone, label: status };
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

/* ------------------------------------------------------------------ Feedback */
export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cx("h-5 w-5 animate-spin text-teal-600", className)} />;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-sm text-slate-500">
      <Spinner /> {label}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const e = error instanceof ApiError ? error : null;
  const title = e?.title || "Error";
  const message = e?.message || (error instanceof Error ? error.message : String(error));
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">
        <div className="font-semibold uppercase tracking-wide">{title}</div>
        <div className="mt-0.5">{message}</div>
        {e?.action && <div className="mt-1 text-xs opacity-80">Action: {e.action}</div>}
      </div>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Notice({ tone = "amber", title, children, icon }: { tone?: "amber" | "red" | "blue" | "green"; title?: ReactNode; children?: ReactNode; icon?: ReactNode }) {
  const styles = {
    amber: "border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100",
    red: "border-red-300 bg-red-50 text-red-950 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100",
    blue: "border-sky-300 bg-sky-50 text-sky-950 dark:border-sky-500/40 dark:bg-sky-500/10 dark:text-sky-100",
    green: "border-emerald-300 bg-emerald-50 text-emerald-950 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-100",
  };
  return (
    <div className={cx("rounded-lg border p-3 text-sm", styles[tone])}>
      <div className="flex items-start gap-2">
        {icon}
        <div className="flex-1">
          {title && <div className="font-semibold">{title}</div>}
          {children && <div className={title ? "mt-1" : ""}>{children}</div>}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <div className="text-slate-400">{icon}</div>
      <div className="font-medium text-slate-700 dark:text-slate-200">{title}</div>
      {children && <div className="max-w-md text-sm text-slate-500 dark:text-slate-400">{children}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ Overlays */
function useEscape(onClose: () => void, enabled = true) {
  useEffect(() => {
    if (!enabled) return;
    const handler = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose, enabled]);
}

export function Modal({ open, onClose, title, children, footer, width = "max-w-lg", dismissable = true }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; width?: string; dismissable?: boolean }) {
  useEscape(onClose, open && dismissable);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/60 p-4 pt-[8vh] backdrop-blur-sm" onMouseDown={(e) => dismissable && e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-modal="true" className={cx("w-full rounded-xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900", width)}>
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <h3 className="text-base font-semibold">{title}</h3>
          {dismissable && (
            <button className="rounded p-1 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={onClose} aria-label="Close">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        <div className="max-h-[75vh] overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, children, footer }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode }) {
  useEscape(onClose, open);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/50 backdrop-blur-[2px]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside className="flex h-full w-full max-w-3xl flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-800">
          <div className="min-w-0 flex-1">{title}</div>
          <button className="rounded p-1.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={onClose} aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800">{footer}</div>}
      </aside>
    </div>
  );
}

/* ------------------------------------------------------------------ Tables & key/values */
export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">{children}</table>
    </div>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cx("border-b border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400", className)}>{children}</th>;
}

export function Td({ children, className, mono }: { children?: ReactNode; className?: string; mono?: boolean }) {
  return <td className={cx("border-b border-slate-100 px-3 py-2 align-top dark:border-slate-800/70", mono && "mono text-[13px]", className)}>{children}</td>;
}

export function KV({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className={cx("mt-0.5 min-w-0 break-words text-sm font-medium text-slate-900 dark:text-slate-100", mono && "mono")}>{children ?? "—"}</dd>
    </div>
  );
}

export function StatCard({ label, value, icon, tone = "slate", hint }: { label: string; value: ReactNode; icon?: ReactNode; tone?: "slate" | "green" | "red" | "amber" | "teal"; hint?: ReactNode }) {
  const accents = {
    slate: "text-slate-500 bg-slate-100 dark:bg-slate-800 dark:text-slate-300",
    green: "text-emerald-700 bg-emerald-100 dark:bg-emerald-500/15 dark:text-emerald-300",
    red: "text-red-700 bg-red-100 dark:bg-red-500/15 dark:text-red-300",
    amber: "text-amber-700 bg-amber-100 dark:bg-amber-500/15 dark:text-amber-300",
    teal: "text-teal-700 bg-teal-100 dark:bg-teal-500/15 dark:text-teal-300",
  };
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</span>
        {icon && <span className={cx("rounded-lg p-1.5", accents[tone])}>{icon}</span>}
      </div>
      <div className="tnum mt-2 text-3xl font-semibold tracking-tight">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</div>}
    </div>
  );
}

export function CodeBlock({ lines }: { lines: string[] }) {
  return (
    <pre className="mono overflow-x-auto rounded-lg bg-slate-950 px-3 py-2.5 text-[13px] leading-relaxed text-emerald-300 ring-1 ring-slate-800">
      {lines.map((l, i) => (
        <div key={i}>
          <span className="select-none text-slate-500">-&gt; </span>
          {l}
        </div>
      ))}
    </pre>
  );
}

const SEVERITY_TONE: Record<string, Tone> = { INFO: "slate", WARNING: "amber", HIGH: "orange", CRITICAL: "red" };

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={SEVERITY_TONE[severity] || "slate"}>{severity}</Badge>;
}
