import { Activity, History, Lock, OctagonX, RotateCcw, ShieldAlert, ShieldCheck, Siren, Wrench } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { LockItem, OperationMode, SafetyEventItem, SafetyResponse, SettingsResponse } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtDateTime, fmtRelative } from "../lib/format";
import { useInterval, useLoader } from "../lib/hooks";
import { notifySafetyChanged } from "../lib/safety";
import { SafetyIndicatorBlock } from "./SafetyIndicator";
import { Badge, Button, Card, EmptyState, ErrorBanner, Field, Input, Loading, Modal, Notice, Table, Td, Th, Toggle, cx } from "./ui";

const RISK_TONE: Record<string, "green" | "red" | "slate"> = { READ_ONLY: "green", STATE_CHANGING: "red" };

const MODES: { mode: OperationMode; title: string; text: string; tone: string }[] = [
  { mode: "NORMAL", title: "Normal", text: "Read-only operations. Restarts are prepared and simulated, never executed.", tone: "border-sky-400" },
  { mode: "MAINTENANCE", title: "Maintenance", text: "Authorized state-changing operations on safe ports, with every safety check.", tone: "border-amber-400" },
  { mode: "READ_ONLY", title: "Read only", text: "No state changes at all. Recommended initial production state.", tone: "border-slate-400" },
  { mode: "EMERGENCY", title: "Emergency", text: "Only administrator-approved emergency operations (e.g. trunk override).", tone: "border-fuchsia-500" },
];

type Pending =
  | { kind: "mode"; mode: OperationMode }
  | { kind: "kill"; active: boolean }
  | { kind: "breaker" };

export function SafetyTab() {
  const { can } = useAuth();
  const isAdmin = can("manage_safety");
  const canStop = can("stop_operations");
  const safety = useLoader(() => api.get<SafetyResponse>("/api/safety"));
  const settings = useLoader(() => api.get<SettingsResponse>("/api/settings"));
  const events = useLoader(() => api.get<{ items: SafetyEventItem[] }>("/api/safety/events", { limit: 30 }));
  const locks = useLoader(() => api.get<{ items: LockItem[] }>("/api/safety/locks"));
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [reason, setReason] = useState("");

  useInterval(() => {
    safety.reload(true);
    locks.reload(true);
  }, 10000);

  async function refreshAll() {
    await Promise.all([safety.reload(true), settings.reload(true), events.reload(true), locks.reload(true)]);
    notifySafetyChanged();
  }

  async function submit() {
    if (!pending) return;
    setError(null);
    try {
      if (pending.kind === "mode") await api.post("/api/safety/mode", { mode: pending.mode, reason });
      if (pending.kind === "kill") await api.post("/api/safety/kill-switch", { active: pending.active, reason });
      if (pending.kind === "breaker") await api.post("/api/safety/breaker/reset", { reason });
      setPending(null);
      setReason("");
      await refreshAll();
    } catch (e) {
      setError(e);
    }
  }

  async function saveSetting(values: Record<string, unknown>) {
    setError(null);
    try {
      settings.setData(await api.put<SettingsResponse>("/api/settings", { values }));
      await refreshAll();
    } catch (e) {
      setError(e);
    }
  }

  if ((safety.loading && !safety.data) || (settings.loading && !settings.data)) return <Loading />;
  if (!safety.data || !settings.data) return <ErrorBanner error={safety.error || settings.error} onRetry={() => refreshAll()} />;
  const s = safety.data;
  const st = s.state;
  const v = settings.data.values;
  const stopped = !st.command_execution_enabled;

  return (
    <div className="space-y-6">
      <ErrorBanner error={error} />
      <div className="grid gap-6 xl:grid-cols-3">
        <Card title="Network safety">
          <SafetyIndicatorBlock indicator={s.indicator} />
          <dl className="mt-4 space-y-3 text-sm">
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">State-changing operations</dt>
              <dd className="font-medium">
                {st.state_changing_block_reason ? (
                  <span className="text-red-700 dark:text-red-400">BLOCKED — {st.state_changing_block_reason}</span>
                ) : (
                  <span className="text-amber-700 dark:text-amber-400">ENABLED (confirmation, verification, dry-run and all safety checks still apply)</span>
                )}
              </dd>
            </div>
            <div className="flex items-center gap-2">
              {s.firewall.ready ? <ShieldCheck className="h-5 w-5 text-emerald-600" /> : <ShieldAlert className="h-5 w-5 text-red-600" />}
              <span>Command Safety Firewall {s.firewall.ready ? "operational" : "FAILED — all commands blocked"}</span>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-slate-500">Policy digest</dt>
              <dd className="mono break-all text-xs">{s.firewall.policy_digest}</dd>
            </div>
          </dl>
        </Card>

        <Card title={<span className="flex items-center gap-2"><Wrench className="h-4 w-4" /> Operation mode</span>} className="xl:col-span-2">
          {st.read_only_forced_by_env && (
            <Notice tone="blue">
              <span className="mono">READ_ONLY_MODE=true</span> is set in the environment: the effective mode is READ_ONLY regardless of the configured mode ({st.configured_mode}).
            </Notice>
          )}
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {MODES.map((m) => {
              const active = st.configured_mode === m.mode;
              return (
                <button
                  key={m.mode}
                  disabled={!isAdmin || active}
                  onClick={() => {
                    setReason("");
                    setPending({ kind: "mode", mode: m.mode });
                  }}
                  className={cx(
                    "rounded-lg border-2 p-3 text-left transition-colors disabled:cursor-default",
                    active ? `${m.tone} bg-slate-50 dark:bg-slate-800` : "border-slate-200 hover:border-slate-400 dark:border-slate-800",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{m.title}</span>
                    {active && <Badge tone="teal">current</Badge>}
                  </div>
                  <p className="mt-1 text-xs text-slate-500">{m.text}</p>
                </button>
              );
            })}
          </div>
          {st.mode_reason && <p className="mt-3 text-sm text-slate-500">Reason: {st.mode_reason}</p>}
          {!isAdmin && <p className="mt-3 text-xs text-slate-500">Only administrators can change the operation mode.</p>}
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><OctagonX className="h-4 w-4" /> Global kill switch</span>}>
          <div className={cx("flex flex-wrap items-center justify-between gap-4 rounded-lg border-2 p-4", stopped ? "border-red-500 bg-red-50 dark:bg-red-500/10" : "border-emerald-300 bg-emerald-50 dark:border-emerald-500/40 dark:bg-emerald-500/10")}>
            <div>
              <div className={cx("text-lg font-bold", stopped ? "text-red-700 dark:text-red-300" : "text-emerald-800 dark:text-emerald-300")}>
                {stopped ? "ALL NETWORK OPERATIONS STOPPED" : "Network operations running"}
              </div>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                STOP ALL NETWORK OPERATIONS blocks every state-changing command immediately. Searches and read-only checks continue. A restart already in progress may still send its restore (port up) command.
              </p>
              {st.kill_switch_forced_by_env && <p className="mt-1 text-sm font-medium">Forced by <span className="mono">NETWORK_COMMAND_EXECUTION=DISABLED</span>.</p>}
            </div>
            {!stopped && canStop && (
              <Button variant="danger" size="lg" icon={<OctagonX className="h-5 w-5" />} onClick={() => { setReason(""); setPending({ kind: "kill", active: true }); }}>
                STOP ALL NETWORK OPERATIONS
              </Button>
            )}
            {stopped && isAdmin && !st.kill_switch_forced_by_env && (
              <Button variant="primary" onClick={() => { setReason(""); setPending({ kind: "kill", active: false }); }}>
                Release kill switch
              </Button>
            )}
          </div>
        </Card>

        <Card title={<span className="flex items-center gap-2"><Siren className="h-4 w-4" /> Circuit breaker</span>}>
          <div className={cx("rounded-lg border-2 p-4", st.safe_mode ? "border-red-500 bg-red-50 dark:bg-red-500/10" : "border-slate-200 dark:border-slate-800")}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="font-semibold">{st.safe_mode ? "SAFE MODE ACTIVE" : "Closed (normal)"}</div>
                {st.safe_mode && <p className="text-sm text-red-700 dark:text-red-300">{st.safe_mode_reason}</p>}
              </div>
              {st.safe_mode && isAdmin && (
                <Button variant="warning" icon={<RotateCcw className="h-4 w-4" />} onClick={() => { setReason(""); setPending({ kind: "breaker" }); }}>
                  Reset SAFE MODE
                </Button>
              )}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
              <Counter label="SSH failures" value={s.breaker.ssh_failures} max={Number(v.breaker_ssh_failures)} />
              <Counter label="Auth failures" value={s.breaker.auth_failures} max={Number(v.breaker_auth_failures)} />
              <Counter label="Validation" value={s.breaker.validation_failures} max={Number(v.breaker_validation_failures)} />
              <Counter label="Unexpected output" value={s.breaker.unexpected_output} max={Number(v.breaker_unexpected_output)} />
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Counted within {String(v.breaker_window_minutes)} minutes. Failures of switches that were already offline are not counted.
            </p>
          </div>
          {s.breaker.recent_events.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-slate-600 dark:text-slate-300">
              {s.breaker.recent_events.slice(-5).map((e, i) => (
                <li key={i} className="mono">{e}</li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Lock className="h-4 w-4" /> Switch and port locks</span>} padded={false}>
          {locks.data && locks.data.items.length === 0 ? (
            <EmptyState title="No active locks">A lock appears while a state-changing operation runs on a switch/port.</EmptyState>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Scope</Th>
                  <Th>Target</Th>
                  <Th>Locked by</Th>
                  <Th>Operation</Th>
                  <Th>Since</Th>
                </tr>
              </thead>
              <tbody>
                {locks.data?.items.map((l) => (
                  <tr key={`${l.scope}-${l.switch_name}-${l.port}`}>
                    <Td><Badge tone={l.scope === "switch" ? "violet" : "blue"}>{l.scope}</Badge></Td>
                    <Td mono>{l.switch_name} {l.port}</Td>
                    <Td>{l.locked_by}</Td>
                    <Td mono>{l.operation}</Td>
                    <Td className="text-slate-500">{fmtRelative(l.acquired_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>

        <Card title={<span className="flex items-center gap-2"><History className="h-4 w-4" /> Safety events</span>} padded={false}>
          {events.data && events.data.items.length === 0 ? (
            <EmptyState title="No safety events yet" />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>Event</Th>
                  <Th>By</Th>
                  <Th>Change</Th>
                  <Th>Reason</Th>
                </tr>
              </thead>
              <tbody>
                {events.data?.items.map((e) => (
                  <tr key={e.id}>
                    <Td className="whitespace-nowrap text-slate-500">{fmtDateTime(e.ts)}</Td>
                    <Td><Badge tone={e.kind === "BREAKER_TRIP" || e.kind === "KILL_SWITCH" ? "red" : "slate"}>{e.kind}</Badge></Td>
                    <Td>{e.username}</Td>
                    <Td mono className="text-xs">{e.old_value} → {e.new_value}</Td>
                    <Td className="text-xs">{e.reason}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>

      <Card title={<span className="flex items-center gap-2"><Activity className="h-4 w-4" /> Limits and thresholds</span>}>
        <div className="grid gap-4 sm:grid-cols-3">
          {(["max_mac_searches_per_minute", "max_restarts_per_10_minutes", "min_port_restart_interval_seconds",
            "breaker_ssh_failures", "breaker_auth_failures", "breaker_validation_failures", "breaker_unexpected_output", "breaker_window_minutes"] as const).map((k) => (
            <RateSetting key={k} name={k} value={Number(v[k])} def={settings.data!.definitions[k]} disabled={!isAdmin} onSave={(n) => saveSetting({ [k]: n })} />
          ))}
        </div>
        <div className="mt-4 flex items-start justify-between gap-4 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
          <div>
            <div className="font-medium">Require lab verification</div>
            <p className="text-sm text-slate-500">{settings.data.definitions.require_lab_verification?.description}</p>
          </div>
          <Toggle checked={Boolean(v.require_lab_verification)} disabled={!isAdmin} label="Require lab verification" onChange={(on) => saveSetting({ require_lab_verification: on })} />
        </div>
      </Card>

      {s.policy && (
        <Card title="Operation policy (authoritative, read-only)" padded={false}>
          <p className="px-4 pt-3 text-sm text-slate-600 dark:text-slate-300">
            The application can only perform these operations and can only send these exact command templates. Anything else is blocked. Changing this list is a reviewed code change, not a setting.
          </p>
          <Table>
            <thead>
              <tr>
                <Th>Operation</Th>
                <Th>Risk</Th>
                <Th>Roles</Th>
                <Th>Max commands</Th>
                <Th>Allowed commands (templates)</Th>
              </tr>
            </thead>
            <tbody>
              {Object.values(s.policy.operations).map((op) => (
                <tr key={op.operation}>
                  <Td>
                    <div className="mono font-medium">{op.operation}</div>
                    <div className="text-xs text-slate-500">{op.description}</div>
                    {!op.api_requestable && <Badge className="mt-1">internal</Badge>}
                  </Td>
                  <Td><Badge tone={RISK_TONE[op.risk] || "slate"}>{op.risk}</Badge></Td>
                  <Td className="text-xs">{op.allowed_roles.join(", ")}</Td>
                  <Td className="tnum">{op.max_commands}</Td>
                  <Td>
                    {Object.entries(op.commands).map(([key, c]) => (
                      <div key={key} className="mb-1">
                        <span className="mono text-xs font-semibold">{key}</span> <span className="text-xs text-slate-500">(max {c.max_per_invocation})</span>
                        {op.risk === "STATE_CHANGING" ? (
                          <div className="text-xs text-slate-500">from a lab-verified bounce strategy</div>
                        ) : (
                          c.allowed_templates.map((t) => (
                            <div key={t} className="mono text-xs text-slate-600 dark:text-slate-300">{t}</div>
                          ))
                        )}
                      </div>
                    ))}
                    {op.notes && <div className="mt-1 text-xs italic text-slate-500">{op.notes}</div>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="grid gap-4 p-4 lg:grid-cols-2">
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">State-changing templates (port bounce only)</div>
              {Object.entries(s.policy.strategies).map(([k, pairs]) => (
                <div key={k} className="mb-2">
                  <div className="mono text-xs font-semibold">{k}</div>
                  {pairs.map((pair) => (
                    <div key={pair.join()} className="mono text-xs text-slate-600 dark:text-slate-300">{pair.join("  →  ")}</div>
                  ))}
                </div>
              ))}
            </div>
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Denied operation categories</div>
              <div className="flex flex-wrap gap-1">
                {s.policy.denied_categories.map((c) => (
                  <Badge key={c} tone="red">{c}</Badge>
                ))}
              </div>
            </div>
          </div>
        </Card>
      )}

      <Modal
        open={!!pending}
        onClose={() => setPending(null)}
        title={
          pending?.kind === "mode"
            ? `Switch to ${pending.mode} mode`
            : pending?.kind === "kill"
              ? pending.active
                ? "STOP ALL NETWORK OPERATIONS"
                : "Release the kill switch"
              : "Reset SAFE MODE"
        }
        footer={
          <>
            <Button onClick={() => setPending(null)}>Cancel</Button>
            <Button variant={pending?.kind === "kill" && pending.active ? "danger" : "primary"} disabled={reason.trim().length < 3} onClick={submit}>
              Confirm
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          {pending?.kind === "mode" && pending.mode === "EMERGENCY" && (
            <Notice tone="red" title="EMERGENCY mode">Administrators can then plan HIGH-RISK operations such as a trunk restart (with two typed confirmations). Operators and simplified users are blocked.</Notice>
          )}
          {pending?.kind === "breaker" && <Notice tone="amber">Only reset after the cause ({st.safe_mode_reason}) has been investigated.</Notice>}
          <Field label="Reason (required, recorded in the audit log)">
            <Input value={reason} maxLength={300} onChange={(e) => setReason(e.target.value)} placeholder="e.g. CHG-1234 access port maintenance" autoFocus />
          </Field>
        </div>
      </Modal>
    </div>
  );
}

function Counter({ label, value, max }: { label: string; value: number; max: number }) {
  const hot = max > 0 && value >= max - 1 && value > 0;
  return (
    <div className="rounded-md bg-slate-50 px-2 py-1.5 dark:bg-slate-800">
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={cx("tnum font-semibold", hot && "text-red-600")}>
        {value} / {max}
      </div>
    </div>
  );
}

const RATE_LABELS: Record<string, string> = {
  max_mac_searches_per_minute: "MAC searches / minute / user",
  max_restarts_per_10_minutes: "Port restarts / 10 min / user",
  min_port_restart_interval_seconds: "Same-port restart interval (s)",
  breaker_ssh_failures: "Breaker: SSH failures",
  breaker_auth_failures: "Breaker: authentication failures",
  breaker_validation_failures: "Breaker: validation failures",
  breaker_unexpected_output: "Breaker: unexpected CLI output",
  breaker_window_minutes: "Breaker window (minutes)",
};

function RateSetting({ name, value, def, disabled, onSave }: { name: string; value: number; def?: { min: number | null; max: number | null }; disabled: boolean; onSave: (n: number) => void }) {
  const [draft, setDraft] = useState(String(value));
  return (
    <Field label={RATE_LABELS[name] || name} hint={def ? `${def.min}–${def.max}` : undefined}>
      <div className="flex gap-2">
        <Input type="number" value={draft} disabled={disabled} min={def?.min ?? undefined} max={def?.max ?? undefined} onChange={(e) => setDraft(e.target.value)} />
        {!disabled && Number(draft) !== value && (
          <Button size="sm" className="h-auto" onClick={() => onSave(Number(draft))}>
            Save
          </Button>
        )}
      </div>
    </Field>
  );
}
