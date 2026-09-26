// Simplified experience for the MAC_OPERATOR role (§61–78).
//
// Deliberately minimal: a MAC address, a switch name and one button. No ports, VLANs, IPs,
// models, commands or technical errors are ever requested or shown. This screen is NOT a
// security boundary: the backend enforces the same checks for every request it receives.
import { CheckCircle2, Loader2, LogOut, Network, RotateCcw, Search, TriangleAlert, XCircle } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { SimpleResult } from "../api/types";
import { useAuth } from "../auth/AuthContext";

const GENERIC = "Something went wrong. Please try again or contact IT support.";

type Phase = "idle" | "searching" | "result" | "confirm" | "restarting" | "done";

async function poll(path: string, stillRunning: (r: SimpleResult) => boolean, signal: { stop: boolean }): Promise<SimpleResult> {
  for (let i = 0; i < 1200 && !signal.stop; i++) {
    const r = await api.get<SimpleResult>(path);
    if (!stillRunning(r)) return r;
    await new Promise((res) => setTimeout(res, 1000));
  }
  return { state: "error", message: GENERIC };
}

export default function SimpleApp() {
  const { user, logout } = useAuth();
  const [mac, setMac] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<SimpleResult | null>(null);
  const [final, setFinal] = useState<SimpleResult | null>(null);
  const signal = useRef({ stop: false });

  useEffect(() => {
    const s = signal.current;
    s.stop = false; // (re)mounted — React StrictMode mounts, unmounts and mounts again
    return () => {
      s.stop = true;
    };
  }, []);

  async function search(e: FormEvent) {
    e.preventDefault();
    if (!mac.trim()) return;
    setPhase("searching");
    setResult(null);
    setFinal(null);
    try {
      const started = await api.post<SimpleResult>("/api/simple/search", { mac });
      const r =
        started.state === "searching" && started.search_id
          ? { ...(await poll(`/api/simple/search/${started.search_id}`, (x) => x.state === "searching", signal.current)), search_id: started.search_id }
          : started;
      setResult(r);
    } catch {
      setResult({ state: "error", message: GENERIC });
    }
    setPhase("result");
  }

  async function restart() {
    if (!result?.search_id) return;
    setPhase("restarting");
    try {
      const started = await api.post<SimpleResult>("/api/simple/restart", { search_id: result.search_id });
      const r =
        started.state === "running" && started.request_id
          ? await poll(`/api/simple/restart/${started.request_id}`, (x) => x.state === "running", signal.current)
          : started;
      setFinal(r);
    } catch {
      setFinal({ state: "error", message: GENERIC });
    }
    setPhase("done");
  }

  function reset() {
    setPhase("idle");
    setResult(null);
    setFinal(null);
    setMac("");
  }

  return (
    <div className="flex min-h-full flex-col bg-slate-100 dark:bg-slate-950">
      <header className="flex items-center justify-between bg-slate-900 px-4 py-3 text-white sm:px-6">
        <div className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-600">
            <Network className="h-5 w-5" />
          </div>
          <span className="text-lg font-semibold">Network Device Tool</span>
        </div>
        <button onClick={logout} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-slate-800" aria-label="Sign out">
          <span className="hidden sm:inline">{user?.full_name || user?.username}</span>
          <LogOut className="h-5 w-5" />
        </button>
      </header>

      <main className="flex flex-1 items-start justify-center px-4 py-10 sm:py-16">
        <div className="w-full max-w-xl rounded-2xl bg-white p-6 shadow-lg dark:bg-slate-900 sm:p-10">
          <form onSubmit={search} className="space-y-5">
            <label htmlFor="simple-mac" className="block text-center text-xl font-semibold">
              Enter MAC Address
            </label>
            <input
              id="simple-mac"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              placeholder="00:11:22:33:44:55"
              autoComplete="off"
              spellCheck={false}
              maxLength={64}
              disabled={phase === "searching" || phase === "restarting"}
              className="mono block h-16 w-full rounded-xl border-2 border-slate-300 bg-white px-4 text-center text-2xl tracking-wider outline-none focus:border-teal-600 dark:border-slate-700 dark:bg-slate-950"
            />
            <button
              type="submit"
              disabled={!mac.trim() || phase === "searching" || phase === "restarting"}
              className="flex h-14 w-full items-center justify-center gap-3 rounded-xl bg-teal-700 text-xl font-semibold text-white hover:bg-teal-800 disabled:opacity-50"
            >
              {phase === "searching" ? <Loader2 className="h-6 w-6 animate-spin" /> : <Search className="h-6 w-6" />}
              {phase === "searching" ? "Searching…" : "SEARCH"}
            </button>
          </form>

          {phase !== "idle" && phase !== "searching" && result && (
            <div className="mt-8" role="status" aria-live="polite">
              {result.state === "found" ? (
                <div className="space-y-5 text-center">
                  <div className="flex items-center justify-center gap-2 text-lg font-semibold text-emerald-700 dark:text-emerald-400">
                    <CheckCircle2 className="h-6 w-6" /> Device Found
                  </div>
                  <div>
                    <div className="text-sm uppercase tracking-wide text-slate-500">Switch</div>
                    <div className="mt-1 text-3xl font-bold" data-testid="simple-switch">
                      {result.switch_name}
                    </div>
                  </div>
                  {phase === "result" && result.can_restart && (
                    <button
                      onClick={() => setPhase("confirm")}
                      className="flex h-14 w-full items-center justify-center gap-3 rounded-xl bg-amber-500 text-xl font-semibold text-slate-950 hover:bg-amber-400"
                    >
                      <RotateCcw className="h-6 w-6" /> RESTART DEVICE
                    </button>
                  )}
                  {phase === "result" && !result.can_restart && (
                    <Message tone="amber" text="This device cannot be restarted automatically. Please contact IT support." />
                  )}
                </div>
              ) : (
                <Message tone={result.state === "not_found" || result.state === "invalid" ? "slate" : "amber"} text={result.message} />
              )}
            </div>
          )}

          {phase === "restarting" && (
            <div className="mt-8 flex items-center justify-center gap-3 text-lg font-medium" role="status">
              <Loader2 className="h-6 w-6 animate-spin text-teal-600" /> Restarting the device… please wait.
            </div>
          )}

          {phase === "done" && final && (
            <div className="mt-8 space-y-4">
              <Message
                tone={final.state === "success" ? "green" : final.state === "success_pending" ? "amber" : "red"}
                text={final.message}
              />
              <button onClick={reset} className="h-12 w-full rounded-xl border-2 border-slate-300 text-lg font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800">
                Search another device
              </button>
            </div>
          )}
        </div>
      </main>

      {phase === "confirm" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
          <div className="w-full max-w-md rounded-2xl bg-white p-8 text-center shadow-2xl dark:bg-slate-900">
            <h2 id="confirm-title" className="text-2xl font-bold">
              Restart Device?
            </h2>
            <p className="mt-3 text-lg text-slate-600 dark:text-slate-300">This may temporarily disconnect the device.</p>
            <div className="mt-8 grid grid-cols-2 gap-3">
              <button onClick={() => setPhase("result")} className="h-14 rounded-xl border-2 border-slate-300 text-lg font-semibold hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800">
                Cancel
              </button>
              <button onClick={restart} className="h-14 rounded-xl bg-amber-500 text-lg font-semibold text-slate-950 hover:bg-amber-400">
                Restart
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Message({ tone, text }: { tone: "green" | "amber" | "red" | "slate"; text: string }) {
  const styles = {
    green: "bg-emerald-50 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300",
    amber: "bg-amber-50 text-amber-900 dark:bg-amber-500/10 dark:text-amber-200",
    red: "bg-red-50 text-red-800 dark:bg-red-500/10 dark:text-red-300",
    slate: "bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
  }[tone];
  const Icon = tone === "green" ? CheckCircle2 : tone === "red" ? XCircle : TriangleAlert;
  return (
    <div className={`flex items-start gap-3 rounded-xl p-5 text-lg ${styles}`}>
      <Icon className="mt-0.5 h-6 w-6 shrink-0" />
      <span>{text}</span>
    </div>
  );
}
