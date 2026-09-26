import { AlertOctagon, AlertTriangle, CheckCircle2, CircleSlash, Loader2, Power, ShieldAlert, XCircle, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { ApiError, api } from "../api/client";
import type { ChangeReport, PortAction, SafetyReport } from "../api/types";
import { useInterval } from "../lib/hooks";
import { formatMac } from "../lib/format";
import { ReasonList } from "./ResultDetails";
import { ActionStatusBadge, Badge, Button, ClassBadge, CodeBlock, ErrorBanner, Field, Input, KV, Modal, Notice, Textarea, cx } from "./ui";

type Target = { searchResultId?: number; switchId?: number; port?: string; mac?: string; switchName: string };
type Stage = "choose" | "preparing" | "plan" | "executing" | "tracking";

const METHODS = [
  { value: "link_bounce", label: "Link bounce", help: "Administratively disable and re-enable the Ethernet port." },
  { value: "poe_cycle", label: "PoE power cycle", help: "Switch PoE power off and on (reboots a powered phone/AP/camera)." },
] as const;

export function RestartDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const [stage, setStage] = useState<Stage>("choose");
  const [method, setMethod] = useState<"link_bounce" | "poe_cycle">("link_bounce");
  const [plan, setPlan] = useState<PortAction | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [phrases, setPhrases] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [now, setNow] = useState(Date.now());

  useInterval(() => setNow(Date.now()), 1000, stage === "plan");

  async function prepare() {
    setStage("preparing");
    setError(null);
    try {
      const p = await api.post<PortAction>("/api/ports/restart/prepare", {
        method,
        search_result_id: target.searchResultId,
        switch_id: target.searchResultId ? undefined : target.switchId,
        port: target.searchResultId ? undefined : target.port,
        mac: target.searchResultId ? undefined : target.mac,
      });
      setPlan(p);
      setPhrases(p.required_phrases.map(() => ""));
      setStage("plan");
    } catch (e) {
      setError(e);
      setStage("choose");
    }
  }

  async function execute() {
    if (!plan) return;
    setStage("executing");
    setError(null);
    try {
      const result = await api.post<PortAction>("/api/ports/restart", { plan_token: plan.plan_token, confirmations: phrases, reason });
      setPlan(result);
      setStage("tracking");
    } catch (e) {
      setError(e);
      if (e instanceof ApiError && e.code === "COMMAND_BLOCKED") {
        // The plan is now closed (denied); show its final state instead of offering a retry.
        setPlan(await api.get<PortAction>(`/api/ports/actions/${plan.id}`).catch(() => plan));
        setStage("tracking");
      } else {
        setStage("plan");
      }
    }
  }

  useInterval(
    async () => {
      if (!plan) return;
      try {
        setPlan(await api.get<PortAction>(`/api/ports/actions/${plan.id}`));
      } catch {
        /* keep polling */
      }
    },
    1000,
    stage === "tracking" && plan?.status === "running",
  );

  const expiresIn = plan?.expires_at ? Math.max(0, Math.round((new Date(plan.expires_at).getTime() - now) / 1000)) : null;
  const allTyped = !!plan && plan.required_phrases.every((p, i) => phrases[i] === p);
  const busy = stage === "preparing" || stage === "executing" || (stage === "tracking" && plan?.status === "running");

  useEffect(() => {
    if (expiresIn === 0 && stage === "plan") setError(new Error("The plan expired. Close this dialog and re-check the port."));
  }, [expiresIn, stage]);

  const high = plan?.risk_level === "high";

  return (
    <Modal
      open
      onClose={onClose}
      dismissable={!busy}
      width="max-w-2xl"
      title={
        <span className="flex items-center gap-2">
          <Power className="h-4 w-4 text-red-600" /> Restart port — {target.switchName}
        </span>
      }
      footer={
        stage === "choose" ? (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={prepare}>
              Re-check &amp; prepare
            </Button>
          </>
        ) : stage === "plan" && plan?.available ? (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant={high ? "danger" : "danger"} disabled={!allTyped || expiresIn === 0} onClick={execute} icon={<Zap className="h-4 w-4" />}>
              {plan.dry_run ? "Run dry run" : "Restart port now"}
            </Button>
          </>
        ) : (
          <Button onClick={onClose} disabled={busy}>
            Close
          </Button>
        )
      }
    >
      <div className="space-y-4">
        <ErrorBanner error={error} />

        {stage === "choose" && (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Before anything is changed, the switch is checked again (read-only): MAC location, port, VLANs and port classification. You will then see the exact commands and must confirm.
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {METHODS.map((m) => (
                <label
                  key={m.value}
                  className={cx(
                    "cursor-pointer rounded-lg border p-3 text-sm",
                    method === m.value ? "border-teal-600 bg-teal-50 ring-2 ring-teal-600/20 dark:bg-teal-500/10" : "border-slate-300 dark:border-slate-700",
                  )}
                >
                  <input type="radio" name="method" className="sr-only" checked={method === m.value} onChange={() => setMethod(m.value)} />
                  <div className="font-semibold">{m.label}</div>
                  <div className="mt-0.5 text-xs text-slate-500">{m.help}</div>
                </label>
              ))}
            </div>
          </>
        )}

        {stage === "preparing" && (
          <div className="flex items-center gap-3 py-8 text-sm text-slate-600 dark:text-slate-300">
            <Loader2 className="h-5 w-5 animate-spin text-teal-600" /> Re-checking MAC, port, VLANs and classification on {target.switchName}…
          </div>
        )}

        {plan && stage !== "choose" && stage !== "preparing" && (
          <>
            {!plan.available ? (
              <Notice tone="red" icon={<CircleSlash className="mt-0.5 h-5 w-5" />} title="PORT RESTART NOT AVAILABLE">
                <div className="mt-1">
                  <span className="font-medium">Reason:</span> {plan.blocked_reason}
                </div>
                <div className="mt-1 text-xs opacity-80">No commands were sent. This attempt has been logged.</div>
              </Notice>
            ) : stage === "plan" ? (
              <div className={cx("rounded-lg border-2 p-4", high ? "border-red-500 bg-red-50 dark:bg-red-500/10" : "border-amber-400 bg-amber-50 dark:bg-amber-500/10")}>
                <div className={cx("flex items-center gap-2 text-sm font-bold uppercase tracking-wide", high ? "text-red-700 dark:text-red-300" : "text-amber-800 dark:text-amber-200")}>
                  {high ? <AlertOctagon className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
                  {high ? "High risk" : "Warning"}
                </div>
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
                  {plan.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            <dl className="grid grid-cols-2 gap-4 rounded-lg border border-slate-200 p-4 sm:grid-cols-4 dark:border-slate-800">
              <KV label="Switch">{plan.switch_name}</KV>
              <KV label="Port" mono>
                <span className="text-lg">{plan.port}</span>
              </KV>
              <KV label="MAC" mono>{formatMac(plan.mac)}</KV>
              <KV label="VLAN" mono>{plan.vlan_id ?? "—"}</KV>
              <KV label="Classification">
                <ClassBadge value={plan.classification} confidence={plan.classification_confidence} />
              </KV>
              <KV label="Method">{plan.method === "poe_cycle" ? "PoE power cycle" : "Link bounce"}</KV>
              <KV label="Strategy" mono>
                <span className="break-words text-[11px]">{plan.strategy || "—"}</span>
              </KV>
              <KV label="AOS" mono>{plan.aos_version}</KV>
            </dl>

            {plan.classification_reasons.length > 0 && stage === "plan" && (
              <details className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800">
                <summary className="cursor-pointer font-medium">Why is this port {plan.classification.replace("_", " ")}?</summary>
                <div className="mt-2">
                  <ReasonList reasons={plan.classification_reasons} />
                </div>
              </details>
            )}

            {plan.commands.length > 0 && (
              <div>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">Command sequence</span>
                  {plan.dry_run ? <Badge tone="blue">DRY RUN — will not be sent</Badge> : <Badge tone="red">LIVE — will be sent</Badge>}
                </div>
                <CodeBlock lines={plan.commands} />
                {!plan.execution_allowed && plan.execution_note && <p className="mt-1.5 text-xs text-slate-500">{plan.execution_note}</p>}
              </div>
            )}
            {stage === "plan" && <SafetyReportPanel action={plan} />}

            {stage === "plan" && plan.available && (
              <div className="space-y-3">
                {plan.required_phrases.map((p, i) => (
                  <Field key={p} label={`Type "${p}" to confirm`}>
                    <Input
                      value={phrases[i] || ""}
                      onChange={(e) => setPhrases((prev) => prev.map((x, j) => (j === i ? e.target.value : x)))}
                      onPaste={(e) => e.preventDefault()}
                      autoComplete="off"
                      spellCheck={false}
                      className={cx("mono", phrases[i] === p && "border-emerald-500")}
                      placeholder={p}
                    />
                  </Field>
                ))}
                <Field label="Reason (recorded in the audit log)">
                  <Textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. User PC not getting DHCP after move" />
                </Field>
                {expiresIn !== null && <p className="text-xs text-slate-500">This plan expires in {expiresIn}s; after that the port must be re-checked.</p>}
              </div>
            )}

            {(stage === "executing" || stage === "tracking") && <ActionProgress action={plan} />}
          </>
        )}
      </div>
    </Modal>
  );
}

export function ActionProgress({ action }: { action: PortAction }) {
  const v = action.verification || {};
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold">Status</span>
        <ActionStatusBadge status={action.status} />
        {action.status === "running" && <Loader2 className="h-4 w-4 animate-spin text-amber-500" />}
      </div>
      <SafetyReportPanel action={action} />
      {action.status === "dry_run" && (
        <Notice tone="blue" icon={<ShieldAlert className="mt-0.5 h-5 w-5" />} title="DRY RUN — NO COMMANDS WERE EXECUTED">
          The command sequence above shows exactly what would have been sent.{" "}
          {action.execution_allowed ? "Dry-run mode is enabled in Settings." : action.execution_note}
        </Notice>
      )}
      {action.status === "success" && (
        <Notice tone={v.mac_learned ? "green" : "amber"} icon={<CheckCircle2 className="mt-0.5 h-5 w-5" />} title="PORT RESTART COMPLETED">
          <dl className="mt-2 grid grid-cols-3 gap-3">
            <KV label="Port">{(v.port_status || "?").toUpperCase()}</KV>
            <KV label="MAC">{v.mac_learned ? "LEARNED" : "NOT YET LEARNED"}</KV>
            <KV label="VLAN" mono>{v.mac_vlan ?? "—"}</KV>
          </dl>
          {!v.mac_learned && <p className="mt-2 text-sm font-semibold">WARNING: MAC has not been relearned</p>}
          {v.vlan_matches === false && <p className="mt-2 text-xs">VLAN membership differs from before the restart — check the port.</p>}
        </Notice>
      )}
      {["success", "failed", "aborted"].includes(action.status) && <ChangeReportPanel actionId={action.id} />}
      {action.status === "denied" && (
        <Notice tone="red" icon={<XCircle className="mt-0.5 h-5 w-5" />} title="PORT RESTART BLOCKED">
          {action.blocked_reason}
        </Notice>
      )}
      {["failed", "aborted", "interrupted"].includes(action.status) && (
        <Notice tone="red" icon={<XCircle className="mt-0.5 h-5 w-5" />} title={action.status === "aborted" ? "ABORTED" : "FAILED"}>
          {action.error_message || action.result_message}
        </Notice>
      )}
      {action.steps.length > 0 && (
        <ol className="space-y-1.5 border-l-2 border-slate-200 pl-4 dark:border-slate-700">
          {action.steps.map((s, i) => (
            <li key={i} className="relative text-sm">
              <span className={cx("absolute -left-[1.4rem] top-1.5 h-2.5 w-2.5 rounded-full", s.ok ? "bg-emerald-500" : "bg-red-500")} />
              <span className="font-medium">{s.step.replace("_", " ")}</span> <span className="text-slate-500">{s.message}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

export function SafetyReportPanel({ action }: { action: PortAction }) {
  const r = action.safety_report as Partial<SafetyReport>;
  if (!r || !("checks" in r) || !r.checks) return null;
  const pass = r.safety === "PASS";
  return (
    <div className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-700">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="font-semibold uppercase tracking-wide">Command safety test</span>
        <Badge tone={pass ? "green" : "red"}>Safety: {r.safety}</Badge>
        <Badge tone={r.execution === "ENABLED" ? "red" : "blue"}>Execution: {r.execution}</Badge>
        <Badge tone="slate">{r.result}</Badge>
      </div>
      {r.execution_reason && <div className="mb-2 text-xs text-slate-500">{r.execution_reason}</div>}
      <div className="space-y-1">
        {(r.commands || []).map((c) => (
          <div key={c.fingerprint} className="flex flex-wrap items-center gap-2 text-xs">
            <span className="mono">{c.text}</span>
            <Badge tone="orange">{c.risk}</Badge>
            <span className="mono text-slate-500">#{c.fingerprint.slice(0, 16)}</span>
          </div>
        ))}
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-slate-500">{r.checks.length} checks</summary>
        <ul className="mt-1 space-y-0.5 text-xs">
          {r.checks.map((c, i) => (
            <li key={i} className={c.ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}>
              {c.ok ? "✓" : "✗"} {c.check}{c.detail ? ` — ${c.detail}` : ""}
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function show(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) {
    return value.map((v) => (typeof v === "object" && v ? `${(v as { vlan_id?: number }).vlan_id ?? JSON.stringify(v)}${(v as { tagged?: boolean }).tagged ? "t" : ""}` : String(v))).join(", ") || "—";
  }
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
}

/** §54 change report: before/after snapshots of the port and what changed. */
export function ChangeReportPanel({ actionId }: { actionId: number }) {
  const [report, setReport] = useState<ChangeReport | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (open && !report) api.get<ChangeReport>(`/api/ports/actions/${actionId}/report`).then(setReport).catch(() => undefined);
  }, [open, report, actionId]);
  return (
    <details className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-700" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer font-semibold">Change report (before / after)</summary>
      {!report ? (
        <div className="mt-2 text-xs text-slate-500">Loading…</div>
      ) : report.changes.length === 0 ? (
        <div className="mt-2 text-xs text-slate-500">No after-snapshot (the port was not changed or verification did not complete).</div>
      ) : (
        <table className="mt-2 w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="py-1">Field</th>
              <th>Before</th>
              <th>After</th>
            </tr>
          </thead>
          <tbody>
            {report.changes.map((c) => (
              <tr key={c.field} className={cx("border-t border-slate-100 dark:border-slate-800", c.changed && "font-semibold text-amber-700 dark:text-amber-400")}>
                <td className="py-1">{c.field.replace(/_/g, " ")}</td>
                <td className="mono">{show(c.before)}</td>
                <td className="mono">{show(c.after)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {report && report.fingerprints.length > 0 && (
        <div className="mt-2 text-[11px] text-slate-500">
          Command fingerprints: {report.fingerprints.map((f) => <span key={f} className="mono mr-2">#{f.slice(0, 16)}</span>)}
        </div>
      )}
    </details>
  );
}
