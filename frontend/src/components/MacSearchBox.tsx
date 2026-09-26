import { Search } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { MacSearch, SearchMode, Switch } from "../api/types";
import { formatMac, normalizeMac } from "../lib/format";
import { Button, ErrorBanner, cx } from "./ui";

export const DEEP_MAX_SWITCHES = 5;

const MODES: { mode: SearchMode; label: string; help: string }[] = [
  { mode: "FAST", label: "Fast", help: "MAC lookup only (1 command per switch)" },
  { mode: "STANDARD", label: "Standard", help: "Lookup + port status, VLANs, LLDP, MAC count" },
  { mode: "DEEP", label: "Deep", help: `All verified diagnostics on up to ${DEEP_MAX_SWITCHES} selected switches` },
];

export function MacSearchBox({ onStarted, initial = "", compact = false }: { onStarted: (id: string) => void; initial?: string; compact?: boolean }) {
  const [value, setValue] = useState(initial);
  const [mode, setMode] = useState<SearchMode>("STANDARD");
  const [switches, setSwitches] = useState<Switch[] | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const normalized = normalizeMac(value);
  const invalid = value.trim().length > 0 && !normalized;
  const deepInvalid = mode === "DEEP" && (selected.length === 0 || selected.length > DEEP_MAX_SWITCHES);

  useEffect(() => {
    if (mode === "DEEP" && switches === null) api.get<Switch[]>("/api/switches").then(setSwitches).catch(setError);
  }, [mode, switches]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!normalized || deepInvalid) return;
    setBusy(true);
    setError(null);
    try {
      const s = await api.post<MacSearch>("/api/mac/search", { mac: value.trim(), mode, ...(mode === "DEEP" ? { switch_ids: selected } : {}) });
      onStarted(s.id);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <div className={cx("flex flex-col gap-3 sm:flex-row sm:items-end", !compact && "sm:items-stretch")}>
        <label className="flex-1">
          <span className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">MAC address</span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="00:11:22:33:44:55 · 00-11-22-33-44-55 · 0011.2233.4455 · 001122334455"
            spellCheck={false}
            autoFocus={!compact}
            aria-invalid={invalid}
            className={cx(
              "mono w-full rounded-lg border bg-white px-4 text-slate-900 placeholder:font-sans placeholder:text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 dark:bg-slate-950 dark:text-slate-100",
              compact ? "h-11 text-base" : "h-14 text-xl",
              invalid ? "border-red-400 focus:ring-red-500/20" : "border-slate-300 focus:border-teal-600 focus:ring-teal-600/20 dark:border-slate-700",
            )}
          />
        </label>
        <Button type="submit" variant="primary" size="lg" className={compact ? "h-11" : "h-14 px-8"} loading={busy} disabled={!normalized || deepInvalid} icon={<Search className="h-5 w-5" />}>
          Search MAC
        </Button>
      </div>
      {!compact && (
        <div className="flex flex-wrap items-center gap-2" role="radiogroup" aria-label="Search mode">
          {MODES.map((m) => (
            <button
              key={m.mode}
              type="button"
              role="radio"
              aria-checked={mode === m.mode}
              onClick={() => setMode(m.mode)}
              title={m.help}
              className={cx(
                "rounded-lg border px-3 py-1.5 text-left text-xs",
                mode === m.mode ? "border-teal-600 bg-teal-50 text-teal-900 dark:bg-teal-500/10 dark:text-teal-200" : "border-slate-300 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800",
              )}
            >
              <span className="font-semibold">{m.label}</span> <span className="opacity-75">· {m.help}</span>
            </button>
          ))}
        </div>
      )}
      {mode === "DEEP" && (
        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800">
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
            Deep mode is never run against the whole network — select 1 to {DEEP_MAX_SWITCHES} switches ({selected.length} selected)
          </div>
          <div className="flex max-h-40 flex-wrap gap-2 overflow-y-auto">
            {(switches || []).filter((s) => s.enabled).map((s) => {
              const on = selected.includes(s.id);
              return (
                <label key={s.id} className={cx("flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-xs", on ? "border-teal-600 bg-teal-50 dark:bg-teal-500/10" : "border-slate-300 dark:border-slate-700")}>
                  <input type="checkbox" checked={on} onChange={() => setSelected((prev) => (on ? prev.filter((x) => x !== s.id) : [...prev, s.id]))} />
                  {s.name}
                </label>
              );
            })}
          </div>
        </div>
      )}
      <div className="h-4 text-xs">
        {normalized && (
          <span className="text-slate-500">
            Normalized: <span className="mono font-medium text-slate-700 dark:text-slate-200">{formatMac(normalized)}</span> — read-only lookup ({mode.toLowerCase()} mode)
          </span>
        )}
        {invalid && <span className="text-red-600 dark:text-red-400">Not a valid MAC address.</span>}
      </div>
      <ErrorBanner error={error} />
    </form>
  );
}
