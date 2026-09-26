import { BookCheck, FlaskConical, KeyRound, LogOut as LogOutIcon, Plug, Plus, ShieldAlert, SlidersHorizontal, Trash2, UserCog, Users } from "lucide-react";
import { useState, type ReactNode } from "react";
import { api } from "../api/client";
import type {
  Credential,
  DiscoveryProfile,
  IntegrationStatus,
  Profile,
  ProfileState,
  Role,
  SettingsResponse,
  Switch,
  User,
  VerificationRecord,
  VerificationRunResult,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Badge, Button, Card, ErrorBanner, Field, Input, Loading, Modal, Notice, PageHeader, Select, Table, Td, Th, Toggle, cx } from "../components/ui";
import { fmtDateTime, fmtRelative } from "../lib/format";
import { useLoader } from "../lib/hooks";

type Tab = "system" | "profiles" | "integrations" | "users" | "roles" | "credentials" | "account";

export default function SettingsPage() {
  const { hasRole } = useAuth();
  const [tab, setTab] = useState<Tab>("system");
  const tabs: { id: Tab; label: string; icon: ReactNode; admin?: boolean }[] = [
    { id: "system", label: "Port actions", icon: <SlidersHorizontal className="h-4 w-4" /> },
    { id: "profiles", label: "Command profiles", icon: <BookCheck className="h-4 w-4" /> },
    { id: "integrations", label: "Integrations", icon: <Plug className="h-4 w-4" /> },
    { id: "users", label: "Users", icon: <Users className="h-4 w-4" />, admin: true },
    { id: "roles", label: "Roles", icon: <ShieldAlert className="h-4 w-4" />, admin: true },
    { id: "credentials", label: "Credentials", icon: <KeyRound className="h-4 w-4" />, admin: true },
    { id: "account", label: "My account", icon: <UserCog className="h-4 w-4" /> },
  ];
  return (
    <>
      <PageHeader title="Settings" subtitle="Port actions, command profiles and lab verification, integrations, users and credentials. Operation modes and the kill switch are under Safety Controls." />
      <div className="mb-6 flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800">
        {tabs
          .filter((t) => !t.admin || hasRole("admin"))
          .map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cx(
                "-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium",
                tab === t.id ? "border-teal-600 text-teal-700 dark:text-teal-300" : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200",
              )}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
      </div>
      {tab === "system" && <SystemSettings />}
      {tab === "profiles" && <ProfilesTab />}
      {tab === "integrations" && <IntegrationsTab />}
      {tab === "users" && <UsersTab />}
      {tab === "roles" && <RolesTab />}
      {tab === "credentials" && <CredentialsTab />}
      {tab === "account" && <AccountTab />}
    </>
  );
}

/* ------------------------------------------------------------------ System */
const LABELS: Record<string, string> = {
  dry_run_mode: "Dry-run mode",
  operator_restart_classes: "Operators may restart",
  port_bounce_hold_seconds: "Hold time between down and up (s)",
  post_restart_verify_seconds: "Post-restart verification timeout (s)",
  restart_plan_ttl_seconds: "Restart plan validity (s)",
  search_include_lldp: "Query LLDP on found ports",
  search_include_mac_count: "Count MACs on found ports",
};

function SystemSettings() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");
  const { data, setData, error, loading, reload } = useLoader(() => api.get<SettingsResponse>("/api/settings"));
  const [saveError, setSaveError] = useState<unknown>(null);
  const [confirmLive, setConfirmLive] = useState(false);

  async function save(values: Record<string, unknown>) {
    setSaveError(null);
    try {
      setData(await api.put<SettingsResponse>("/api/settings", { values }));
      window.dispatchEvent(new Event("settings-changed"));
    } catch (e) {
      setSaveError(e);
    }
  }

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  if (!data) return null;
  const v = data.values;

  return (
    <div className="grid gap-6 xl:grid-cols-3">
      <Card title="Port action safety" className="xl:col-span-2">
        <div className="space-y-5">
          <ErrorBanner error={saveError} />
          <div className="flex items-start justify-between gap-4 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
            <div>
              <div className="font-medium">{LABELS.dry_run_mode}</div>
              <p className="text-sm text-slate-500">{data.definitions.dry_run_mode.description}</p>
              {!v.dry_run_mode && (
                <p className="mt-1 text-sm font-medium text-amber-700 dark:text-amber-400">Live mode: approved restart strategies will send commands to switches.</p>
              )}
            </div>
            <Toggle
              checked={Boolean(v.dry_run_mode)}
              disabled={!isAdmin}
              label="Dry-run mode"
              onChange={(on) => (on ? save({ dry_run_mode: true }) : setConfirmLive(true))}
            />
          </div>
          <Notice tone="blue" title="Trunk and infrastructure ports">
            Restarting a TRUNK / LIKELY TRUNK port, or any port of a core/distribution switch, is possible only for administrators while the operation mode is <strong>EMERGENCY</strong> (Safety Controls), with two typed confirmations. UNKNOWN ports, declared uplinks and link aggregates can never be restarted.
          </Notice>
          <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800">
            <div className="font-medium">{LABELS.operator_restart_classes}</div>
            <p className="mb-2 text-sm text-slate-500">Operators can never restart UNKNOWN, LIKELY TRUNK or TRUNK ports. The simplified MAC_OPERATOR flow only ever restarts confidently classified ACCESS ports.</p>
            <div className="flex gap-4">
              {data.definitions.operator_restart_classes.choices.map((c) => {
                const list = (v.operator_restart_classes as string[]) || [];
                return (
                  <label key={c} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      disabled={!isAdmin}
                      checked={list.includes(c)}
                      onChange={(e) => save({ operator_restart_classes: e.target.checked ? [...list, c] : list.filter((x) => x !== c) })}
                    />
                    {c.replace("_", " ")}
                  </label>
                );
              })}
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-3">
            {(["port_bounce_hold_seconds", "post_restart_verify_seconds", "restart_plan_ttl_seconds"] as const).map((k) => (
              <NumberSetting key={k} label={LABELS[k]} value={Number(v[k])} def={data.definitions[k]} disabled={!isAdmin} onSave={(n) => save({ [k]: n })} />
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {(["search_include_lldp", "search_include_mac_count"] as const).map((k) => (
              <div key={k} className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                <span className="text-sm font-medium">{LABELS[k]}</span>
                <Toggle checked={Boolean(v[k])} disabled={!isAdmin} label={LABELS[k]} onChange={(on) => save({ [k]: on })} />
              </div>
            ))}
          </div>
        </div>
      </Card>
      <Card title="Environment (read-only)">
        <dl className="space-y-3 text-sm">
          {Object.entries(data.environment).map(([k, val]) => (
            <div key={k} className="flex justify-between gap-3">
              <dt className="text-slate-500">{k.replace(/_/g, " ")}</dt>
              <dd className="mono font-medium">
                {k === "ssh_allow_unknown_host_keys" && val ? <Badge tone="red">ON (lab only!)</Badge> : String(val)}
              </dd>
            </div>
          ))}
        </dl>
        <p className="mt-4 text-xs text-slate-500">Set via environment variables (.env) and applied on restart.</p>
      </Card>
      <Modal
        open={confirmLive}
        onClose={() => setConfirmLive(false)}
        title="Enable live port actions?"
        footer={
          <>
            <Button onClick={() => setConfirmLive(false)}>Keep dry-run</Button>
            <Button
              variant="danger"
              onClick={() => {
                setConfirmLive(false);
                save({ dry_run_mode: false });
              }}
            >
              Enable live mode
            </Button>
          </>
        }
      >
        <Notice tone="red" icon={<ShieldAlert className="mt-0.5 h-5 w-5" />} title="Commands will be sent to switches">
          With dry-run off, confirmed restarts using a <strong>lab-verified</strong> strategy send the port-down and port-up commands to the switch — and only while the operation mode is MAINTENANCE. Only disable dry-run after the strategy was validated on a lab switch for each model family and AOS version.
        </Notice>
      </Modal>
    </div>
  );
}

function NumberSetting({ label, value, def, disabled, onSave }: { label: string; value: number; def: { min: number | null; max: number | null }; disabled: boolean; onSave: (n: number) => void }) {
  const [draft, setDraft] = useState(String(value));
  return (
    <Field label={label} hint={`${def.min}–${def.max}`}>
      <div className="flex gap-2">
        <Input type="number" min={def.min ?? undefined} max={def.max ?? undefined} value={draft} disabled={disabled} onChange={(e) => setDraft(e.target.value)} />
        {!disabled && Number(draft) !== value && (
          <Button size="sm" className="h-auto" onClick={() => onSave(Number(draft))}>
            Save
          </Button>
        )}
      </div>
    </Field>
  );
}

/* ------------------------------------------------------------------ Profiles */
const VERIF_TONE: Record<string, "green" | "teal" | "blue" | "red"> = { doc_example: "green", doc_syntax: "teal", lab_verified: "blue", unverified: "red" };
const STATE_TONE: Record<string, "green" | "blue" | "red" | "slate"> = {
  PRODUCTION_VERIFIED: "green",
  LAB_VERIFIED: "blue",
  BLOCKED: "red",
  DEPRECATED: "slate",
};
// Allowed profile-state transitions (the server enforces the same rules and the evidence).
const TRANSITIONS: Record<ProfileState, ProfileState[]> = {
  LAB_VERIFIED: ["PRODUCTION_VERIFIED", "BLOCKED", "DEPRECATED"],
  PRODUCTION_VERIFIED: ["LAB_VERIFIED", "BLOCKED", "DEPRECATED"],
  BLOCKED: ["LAB_VERIFIED", "DEPRECATED"],
  DEPRECATED: ["LAB_VERIFIED"],
};
const PREFIX_RE = /^\d{1,2}\.\d{1,3}(\.\d{1,3}){0,2}$/;

function ProfilesTab() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");
  const { data, setData, error, loading, reload } = useLoader(() =>
    api.get<{ profiles: Profile[]; verifications: VerificationRecord[]; capabilities: string[]; discovery_profiles: DiscoveryProfile[] }>("/api/profiles"),
  );
  const [verifyFor, setVerifyFor] = useState<{ profile: Profile; capability: string } | null>(null);
  const [form, setForm] = useState({ model_family: "", version_prefix: "", notes: "" });
  const [stateFor, setStateFor] = useState<VerificationRecord | null>(null);
  const [stateForm, setStateForm] = useState<{ status: ProfileState | ""; reason: string }>({ status: "", reason: "" });
  const [actionError, setActionError] = useState<unknown>(null);
  const [cloning, setCloning] = useState<Profile | null>(null);
  const [cloneKey, setCloneKey] = useState("");
  const [runOpen, setRunOpen] = useState(false);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  if (!data) return null;

  async function addVerification() {
    setActionError(null);
    try {
      const r = await api.post<{ verifications: VerificationRecord[] }>("/api/profiles/verifications", {
        profile_key: verifyFor!.profile.key,
        capability: verifyFor!.capability,
        model_family: form.model_family,
        version_prefix: form.version_prefix.trim(),
        notes: form.notes,
      });
      setData({ ...data!, verifications: r.verifications });
      setVerifyFor(null);
    } catch (e) {
      setActionError(e);
    }
  }

  async function changeState() {
    setActionError(null);
    try {
      const r = await api.post<{ verifications: VerificationRecord[] }>(`/api/profiles/verifications/${stateFor!.id}/status`, {
        status: stateForm.status,
        reason: stateForm.reason.trim(),
      });
      setData({ ...data!, verifications: r.verifications });
      setStateFor(null);
    } catch (e) {
      setActionError(e);
    }
  }

  async function clone() {
    setActionError(null);
    try {
      await api.post("/api/profiles", { key: cloneKey.trim().toUpperCase(), name: `${cloning!.name} (custom)`, clone_from: cloning!.key });
      setCloning(null);
      reload();
    } catch (e) {
      setActionError(e);
    }
  }

  function records(profile: string, capability: string) {
    return data!.verifications.filter((v) => v.profile_key === profile && v.capability === capability);
  }

  function VerifiedBadges({ profile, capability }: { profile: Profile; capability: string }) {
    const list = records(profile.key, capability);
    return (
      <div className="flex flex-wrap items-center gap-1">
        {list.length === 0 && <span className="text-xs text-slate-500">DRAFT — not verified</span>}
        {list.map((v) => (
          <Badge key={v.id} tone={STATE_TONE[v.status] || "slate"}>
            <span
              title={`${v.status}${v.all_models ? " (all models: counts as LAB_VERIFIED at most)" : ""} · ${v.verified_by} · ${fmtDateTime(v.verified_at)}${
                v.status_reason ? " · " + v.status_reason : ""
              }${v.notes ? " · " + v.notes : ""}`}
            >
              {v.all_models ? "all models" : v.model_family} · {v.version_prefix} · {v.effective_level.replace("_VERIFIED", "").toLowerCase()}
            </span>
            {isAdmin && (
              <button
                onClick={() => {
                  setStateFor(v);
                  setStateForm({ status: "", reason: "" });
                  setActionError(null);
                }}
                className="ml-1 opacity-60 hover:opacity-100"
                aria-label={`Change state of ${v.capability} ${v.model_family} ${v.version_prefix}`}
              >
                ⋯
              </button>
            )}
          </Badge>
        ))}
        {isAdmin && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setVerifyFor({ profile, capability });
              setForm({ model_family: profile.supported_models[0] || "", version_prefix: "", notes: "" });
            }}
          >
            + Record
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Notice tone="blue" title="How commands are verified">
        Built-in commands come from the ALE OmniSwitch CLI Reference Guides and are tested against documented output fixtures (evidence level{" "}
        <strong>FIXTURE_TESTED</strong>). That never enables execution on its own. Each capability — READ for the read-only commands and every restart strategy
        separately — has a state per <strong>model family and AOS version</strong>: no record = <strong>DRAFT</strong> (unusable), <strong>LAB_VERIFIED</strong> (lab
        switches and reads), <strong>PRODUCTION_VERIFIED</strong> (state changes on production switches — requires recorded evidence from a real lab switch),{" "}
        <strong>BLOCKED</strong> or <strong>DEPRECATED</strong>. Simulator runs are SIMULATED evidence and are never recorded. See{" "}
        <span className="mono">docs/ALCATEL_COMMAND_PROFILES.md</span>.
      </Notice>
      {data.discovery_profiles?.length > 0 && (
        <Card title="Discovery Profile Registry (identifies a switch before any other command)" padded={false}>
          <Table>
            <thead>
              <tr>
                <Th>Entry</Th>
                <Th>Command</Th>
                <Th>Identifies</Th>
                <Th>Expected output</Th>
                <Th>Source</Th>
              </tr>
            </thead>
            <tbody>
              {data.discovery_profiles.map((d) => (
                <tr key={d.key}>
                  <Td mono>{d.key}</Td>
                  <Td mono>
                    {d.command} <Badge tone="green">{d.safety}</Badge>
                  </Td>
                  <Td className="text-xs">
                    {d.vendor} {d.generation}: <span className="mono">{d.model_families.join(", ")}</span> · AOS <span className="mono">{d.aos_versions.join(", ")}</span>
                  </Td>
                  <Td mono className="text-xs">
                    {d.expected_patterns.map((pat) => (
                      <div key={pat}>{pat}</div>
                    ))}
                  </Td>
                  <Td className="text-xs text-slate-500">
                    {d.sources.join("; ")} <Badge tone={VERIF_TONE[d.verification] || "red"}>{d.verification}</Badge>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {isAdmin && (
        <div>
          <Button icon={<FlaskConical className="h-4 w-4" />} onClick={() => setRunOpen(true)}>
            Run read-only verification on a lab switch…
          </Button>
        </div>
      )}
      <ErrorBanner error={actionError} />
      {data.profiles.map((p) => (
        <Card
          key={p.key}
          title={
            <span className="flex flex-wrap items-center gap-2">
              <span className="mono">{p.key}</span> <span className="font-normal text-slate-500">{p.name}</span>
              {p.builtin ? <Badge tone="teal">built-in</Badge> : <Badge tone="violet">custom</Badge>}
              {!p.enabled && <Badge tone="red">disabled</Badge>}
              <Badge>{p.switch_count} switches</Badge>
              {p.evidence_level && <Badge tone="blue">{p.evidence_level}</Badge>}
              {p.version && <span className="mono text-xs font-normal text-slate-500">v{p.version}</span>}
            </span>
          }
          actions={
            isAdmin && (
              <Button
                size="sm"
                onClick={() => {
                  setCloning(p);
                  setCloneKey(`${p.key}_CUSTOM`);
                }}
              >
                Clone
              </Button>
            )
          }
          padded={false}
        >
          <div className="space-y-2 px-4 pt-3 text-sm">
            <p className="text-slate-600 dark:text-slate-300">{p.description}</p>
            <div className="flex flex-wrap gap-4 text-xs">
              <span>
                <span className="font-semibold uppercase tracking-wide text-slate-500">Supported models</span>{" "}
                <span className="mono">{(p.supported_models || []).join(", ") || "—"}</span>
              </span>
              <span>
                <span className="font-semibold uppercase tracking-wide text-slate-500">AOS versions</span>{" "}
                <span className="mono">{(p.supported_versions || p.version_prefixes).join(", ")}</span>
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-semibold uppercase tracking-wide text-slate-500">Read commands verified for</span>
              <VerifiedBadges profile={p} capability="READ" />
            </div>
          </div>
          <Table>
            <thead>
              <tr>
                <Th>Read-only command</Th>
                <Th>Template</Th>
                <Th>Output contract</Th>
                <Th>Verification</Th>
                <Th>Source / verified by</Th>
              </tr>
            </thead>
            <tbody>
              {Object.values(p.commands).map((c) => (
                <tr key={c.name}>
                  <Td mono>{c.name}</Td>
                  <Td mono>{c.template}</Td>
                  <Td className="text-xs">
                    <div className="mono">{c.parser || "—"}</div>
                    {c.expected_output && <div className="mono text-slate-500" title="Expected output (regex)">{c.expected_output}</div>}
                  </Td>
                  <Td>
                    <Badge tone={VERIF_TONE[c.verification] || "red"}>{c.verification}</Badge>
                  </Td>
                  <Td className="text-xs text-slate-500">
                    {c.source}
                    {c.verified_by && (
                      <div>
                        {c.verified_by}
                        {c.verified_at ? ` · ${c.verified_at}` : ""}
                      </div>
                    )}
                    {c.notes && <div className="italic">{c.notes}</div>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
          {p.strategies.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <Th>Restart strategy</Th>
                  <Th>Commands</Th>
                  <Th>Documentation</Th>
                  <Th>Profile state per model / AOS</Th>
                </tr>
              </thead>
              <tbody>
                {p.strategies.map((st) => (
                  <tr key={st.strategy}>
                    <Td>
                      <div className="mono font-medium">{st.strategy}</div>
                      <div className="text-xs text-slate-500">{st.method === "poe_cycle" ? "PoE power cycle" : "Link bounce"}</div>
                      {st.unsupported_models.length > 0 && <div className="text-xs text-slate-500">Not on: {st.unsupported_models.join(", ")}</div>}
                    </Td>
                    <Td mono className="text-xs">
                      <div>{st.down_template}</div>
                      <div>{st.up_template}</div>
                    </Td>
                    <Td>
                      <Badge tone={VERIF_TONE[st.verification] || "red"}>{st.verification}</Badge>
                      <div className="mt-1 text-xs text-slate-500">{st.source}</div>
                    </Td>
                    <Td>{st.verified ? <VerifiedBadges profile={p} capability={st.strategy} /> : <span className="text-xs text-slate-500">unverified syntax — cannot be recorded</span>}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      ))}

      <Modal
        open={!!verifyFor}
        onClose={() => setVerifyFor(null)}
        title={`Record lab verification: ${verifyFor?.profile.key} · ${verifyFor?.capability}`}
        footer={
          <>
            <Button onClick={() => setVerifyFor(null)}>Cancel</Button>
            <Button variant="primary" disabled={!form.model_family || !PREFIX_RE.test(form.version_prefix.trim())} onClick={addVerification}>
              Record LAB_VERIFIED
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Notice tone="amber" title="Only record after a supervised lab test">
            {verifyFor?.capability === "READ"
              ? "Prefer the automated read-only verification run, which checks every command's output contract."
              : "Prepare a dry run on a lab switch of this model family and AOS version, run the two displayed commands by hand on the lab switch console and confirm the port went down and came back up. Then record it here; the application executes the strategy only for recorded model families and versions."}
          </Notice>
          <Field label="Model family" hint="The exact model family tested. Nobody verifies every model at once.">
            <Select value={form.model_family} onChange={(e) => setForm({ ...form, model_family: e.target.value })}>
              {verifyFor?.profile.supported_models.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </Select>
          </Field>
          <Field label="AOS version (major.minor at least)" hint={`Must belong to ${verifyFor?.profile.key} (${verifyFor?.profile.version_prefixes.join(", ")}). Example: 8.10 or 6.7`}>
            <Input className="mono" value={form.version_prefix} onChange={(e) => setForm({ ...form, version_prefix: e.target.value })} placeholder="8.10" />
          </Field>
          <Field label="Evidence / notes">
            <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="Validated on OS6860E lab switch 8.10.94.R03, 2026-09-25" />
          </Field>
          <ErrorBanner error={actionError} />
        </div>
      </Modal>

      <Modal
        open={!!stateFor}
        onClose={() => setStateFor(null)}
        title={`Profile state: ${stateFor?.profile_key} · ${stateFor?.capability} · ${stateFor?.model_family} AOS ${stateFor?.version_prefix}`}
        footer={
          <>
            <Button onClick={() => setStateFor(null)}>Cancel</Button>
            <Button variant="primary" disabled={!stateForm.status || stateForm.reason.trim().length < 3} onClick={changeState}>
              Change state
            </Button>
          </>
        }
      >
        {stateFor && (
          <div className="space-y-4 text-sm">
            <p>
              Current state: <Badge tone={STATE_TONE[stateFor.status] || "slate"}>{stateFor.status}</Badge>
              {stateFor.status_changed_by && (
                <span className="text-xs text-slate-500">
                  {" "}
                  by {stateFor.status_changed_by} · {fmtDateTime(stateFor.status_changed_at)} · {stateFor.status_reason}
                </span>
              )}
            </p>
            <Field label="New state">
              <Select value={stateForm.status} onChange={(e) => setStateForm({ ...stateForm, status: e.target.value as ProfileState })}>
                <option value="">Select…</option>
                {TRANSITIONS[stateFor.status].map((t) => (
                  <option key={t} value={t} disabled={t === "PRODUCTION_VERIFIED" && stateFor.all_models}>
                    {t}
                    {t === "DEPRECATED" ? " (revoke, kept for history)" : ""}
                  </option>
                ))}
              </Select>
            </Field>
            {stateForm.status === "PRODUCTION_VERIFIED" && (
              <Notice tone="amber" title="Evidence from a real switch is required">
                {stateFor.capability === "READ"
                  ? "A passed read-only verification run on a real (SSH) switch of this model family and AOS version must be recorded."
                  : `A live ${stateFor.capability} restart on a real (SSH) switch of this model family and AOS version whose post-restart verification succeeded must be recorded.`}{" "}
                The server checks it; nothing is promoted automatically.
              </Notice>
            )}
            <Field label="Reason (audited)">
              <Input value={stateForm.reason} onChange={(e) => setStateForm({ ...stateForm, reason: e.target.value })} placeholder="Validated on lab switch LAB-6860-01, change CHG-1234" />
            </Field>
            <ErrorBanner error={actionError} />
          </div>
        )}
      </Modal>

      {runOpen && (
        <VerificationRunModal
          onClose={() => setRunOpen(false)}
          onRecorded={() => {
            setRunOpen(false);
            reload();
          }}
        />
      )}

      <Modal
        open={!!cloning}
        onClose={() => setCloning(null)}
        title={`Clone ${cloning?.key}`}
        footer={
          <>
            <Button onClick={() => setCloning(null)}>Cancel</Button>
            <Button variant="primary" onClick={clone}>
              Create custom profile
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm">A custom profile starts disabled. Edited commands become <em>unverified</em> until marked lab-verified, and all templates must pass the safety linter (read commands: <span className="mono">show …</span> only).</p>
          <Field label="Profile key">
            <Input className="mono" value={cloneKey} onChange={(e) => setCloneKey(e.target.value)} />
          </Field>
          <ErrorBanner error={actionError} />
        </div>
      </Modal>
    </div>
  );
}

function VerificationRunModal({ onClose, onRecorded }: { onClose: () => void; onRecorded: () => void }) {
  const switches = useLoader(() => api.get<Switch[]>("/api/switches"));
  const [switchId, setSwitchId] = useState<number | "">("");
  const [port, setPort] = useState("");
  const [mac, setMac] = useState("");
  const [result, setResult] = useState<VerificationRunResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function run(record: boolean) {
    setBusy(true);
    setErr(null);
    try {
      const r = await api.post<VerificationRunResult>("/api/profiles/verifications/run", { switch_id: switchId, port: port.trim(), mac: mac.trim() || undefined, record });
      setResult(r);
      if (record && r.recorded) onRecorded();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      width="max-w-2xl"
      title="Read-only lab verification"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button onClick={() => run(false)} loading={busy} disabled={!switchId || !port.trim()}>
            Run checks
          </Button>
          <Button variant="primary" onClick={() => run(true)} loading={busy} disabled={!result?.passed || result?.transport === "simulator"}>
            Record READ as LAB_VERIFIED
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Runs each read-only command of the switch's profile once against a sample port and validates the output against its documented contract. No state-changing command exists on this path. Use a <strong>lab</strong> switch.
        </p>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Switch">
            <Select value={switchId} onChange={(e) => setSwitchId(e.target.value ? Number(e.target.value) : "")}>
              <option value="">Select…</option>
              {switches.data?.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.discovery_status === "discovered" ? `${s.model} · ${s.aos_version}` : "not discovered"})
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Sample port">
            <Input className="mono" value={port} onChange={(e) => setPort(e.target.value)} placeholder="1/1/26" />
          </Field>
          <Field label="Sample MAC (optional)">
            <Input className="mono" value={mac} onChange={(e) => setMac(e.target.value)} placeholder="00:11:22:33:44:55" />
          </Field>
        </div>
        <ErrorBanner error={err} />
        {result && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <Badge tone={result.passed ? "green" : "red"}>{result.passed ? "PASSED" : "FAILED"}</Badge>
              <span>
                {result.profile} on {result.model_family} AOS {result.aos_version}
              </span>
              {result.evidence_level && <Badge tone={result.evidence_level === "SIMULATED" ? "slate" : "blue"}>{result.evidence_level}</Badge>}
            </div>
            <ul className="space-y-1 text-xs">
              {result.results.map((r) => (
                <li key={r.command_key} className={cx(r.status === "ok" ? "text-emerald-700 dark:text-emerald-400" : r.status.startsWith("not_") ? "text-slate-500" : "text-red-700 dark:text-red-400")}>
                  <span className="mono font-semibold">{r.command_key}</span> — {r.status.replace(/_/g, " ")}
                  {r.detail ? `: ${r.detail}` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ Integrations */
function IntegrationsTab() {
  const status = useLoader(() => api.get<IntegrationStatus>("/api/integrations/status"));
  if (status.loading && !status.data) return <Loading />;
  if (!status.data) return <ErrorBanner error={status.error} onRetry={() => status.reload()} />;
  const rows: { key: "netbox" | "zabbix"; name: string; env: string; purpose: string }[] = [
    { key: "netbox", name: "NetBox", env: "NETBOX_URL / NETBOX_TOKEN", purpose: "Source of truth: device, role, IP and interface VLANs are compared with live data. Differences become NetBox-mismatch alerts." },
    { key: "zabbix", name: "Zabbix", env: "ZABBIX_URL / ZABBIX_TOKEN", purpose: "Monitoring: host state and current problems are shown on the switch page." },
  ];
  return (
    <div className="space-y-6">
      <Notice tone="blue" title="Read-only by construction">
        The NetBox client can only send HTTP GET to three documented endpoints; the Zabbix client can only call apiinfo.version, host.get and problem.get. Nothing is ever written to NetBox or Zabbix. Use read-only API tokens.
      </Notice>
      <div className="grid gap-6 lg:grid-cols-2">
        {rows.map((r) => {
          const st = status.data![r.key];
          return (
            <Card key={r.key} title={r.name} actions={!st.configured ? <Badge>not configured</Badge> : st.reachable ? <Badge tone="green">reachable</Badge> : <Badge tone="red">unreachable</Badge>}>
              <p className="text-sm text-slate-600 dark:text-slate-300">{r.purpose}</p>
              <p className="mt-2 text-xs text-slate-500">
                Configure with <span className="mono">{r.env}</span> in the environment.
              </p>
              {st.error && <p className="mt-2 text-sm text-red-700 dark:text-red-400">{st.error}</p>}
              {st.info !== undefined && <pre className="mono mt-2 text-xs text-slate-500">{JSON.stringify(st.info)}</pre>}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Users */
function UsersTab() {
  const { user: me } = useAuth();
  const { data, error, loading, reload } = useLoader(() => api.get<User[]>("/api/users"));
  const [editing, setEditing] = useState<User | "new" | null>(null);
  const [form, setForm] = useState({ username: "", full_name: "", role: "readonly" as Role, password: "", is_active: true });
  const [formError, setFormError] = useState<unknown>(null);

  function open(u: User | "new") {
    setFormError(null);
    setEditing(u);
    setForm(u === "new" ? { username: "", full_name: "", role: "readonly", password: "", is_active: true } : { username: u.username, full_name: u.full_name, role: u.role, password: "", is_active: u.is_active });
  }

  async function submit() {
    setFormError(null);
    try {
      if (editing === "new") await api.post("/api/users", form);
      else if (editing) await api.patch(`/api/users/${editing.id}`, { full_name: form.full_name, role: form.role, is_active: form.is_active, ...(form.password ? { password: form.password } : {}) });
      setEditing(null);
      reload();
    } catch (e) {
      setFormError(e);
    }
  }

  async function forceLogout(u: User) {
    if (!confirm(`Sign ${u.username} out of all sessions now?`)) return;
    try {
      await api.post(`/api/users/${u.id}/logout`);
      reload();
    } catch (e) {
      setFormError(e);
    }
  }

  async function remove(u: User) {
    if (!confirm(`Delete user ${u.username}?`)) return;
    try {
      await api.del(`/api/users/${u.id}`);
      reload();
    } catch (e) {
      setFormError(e);
    }
  }

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  return (
    <Card
      title="Users"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />} onClick={() => open("new")}>
          Add user
        </Button>
      }
    >
      <div className="px-4 pt-3 text-xs text-slate-500">
        <strong>MAC operator:</strong> simplified screen only — search a MAC, see the switch name, restart a confidently classified access port. <strong>Read only:</strong> technical search and views. <strong>Operator:</strong> + restart ACCESS ports, engage the kill switch. <strong>Admin:</strong> everything, including modes, inventory, credentials, profiles and emergency operations.
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Username</Th>
            <Th>Name</Th>
            <Th>Role</Th>
            <Th>Status</Th>
            <Th>Sessions</Th>
            <Th>Last login</Th>
            <Th />
          </tr>
        </thead>
        <tbody>
          {data?.map((u) => (
            <tr key={u.id}>
              <Td className="font-medium">{u.username}</Td>
              <Td>{u.full_name}</Td>
              <Td>
                <Badge tone={u.role === "admin" ? "red" : u.role === "operator" ? "amber" : u.role === "mac_operator" ? "blue" : "slate"}>{u.role}</Badge>
              </Td>
              <Td>{u.is_active ? <Badge tone="green">active</Badge> : <Badge>disabled</Badge>}</Td>
              <Td className="tnum">{u.active_sessions ?? 0}</Td>
              <Td className="text-slate-500">{fmtRelative(u.last_login_at)}</Td>
              <Td className="text-right">
                <Button size="sm" variant="ghost" onClick={() => open(u)}>
                  Edit
                </Button>
                {u.id !== me?.id && (u.active_sessions ?? 0) > 0 && (
                  <Button size="sm" variant="ghost" icon={<LogOutIcon className="h-3.5 w-3.5" />} onClick={() => forceLogout(u)}>
                    Force logout
                  </Button>
                )}
                {u.id !== me?.id && (
                  <Button size="sm" variant="ghost" icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => remove(u)}>
                    Delete
                  </Button>
                )}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "Add user" : `Edit ${form.username}`}
        footer={
          <>
            <Button onClick={() => setEditing(null)}>Cancel</Button>
            <Button variant="primary" onClick={submit}>
              Save
            </Button>
          </>
        }
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Username">
            <Input value={form.username} disabled={editing !== "new"} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </Field>
          <Field label="Full name">
            <Input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          </Field>
          <Field label="Role">
            <Select value={form.role} disabled={editing !== "new" && editing?.id === me?.id} title={editing !== "new" && editing?.id === me?.id ? "You cannot change your own role" : undefined} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              <option value="mac_operator">MAC operator (simplified)</option>
              <option value="readonly">Read only</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </Select>
          </Field>
          <Field label={editing === "new" ? "Password" : "New password (optional)"} hint="12+ characters, 3 of: lower, upper, digit, symbol">
            <Input type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </Field>
          {editing !== "new" && editing?.id !== me?.id && (
            <label className="flex items-center gap-2 text-sm">
              <Toggle checked={form.is_active} onChange={(v) => setForm({ ...form, is_active: v })} label="Active" /> Active
            </label>
          )}
          <div className="sm:col-span-2">
            <ErrorBanner error={formError} />
          </div>
        </div>
      </Modal>
    </Card>
  );
}

/* ------------------------------------------------------------------ Roles */
const ROLE_LABEL: Record<string, string> = { mac_operator: "MAC operator", readonly: "Read only", operator: "Operator", admin: "Admin" };

function RolesTab() {
  const { data, error, loading, reload } = useLoader(() =>
    api.get<{ roles: { role: string; permissions: string[] }[]; permissions: { permission: string; description: string }[] }>("/api/roles"),
  );
  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  if (!data) return null;
  return (
    <Card title="Roles and permissions (fixed, enforced by the server on every request)" padded={false}>
      <p className="px-4 pt-3 text-xs text-slate-500">
        Roles are defined in code and cannot be edited here; assign a role to a user in the Users tab. A user can never change their own role. The MAC operator role is deliberately separate from the others.
      </p>
      <Table>
        <thead>
          <tr>
            <Th>Permission</Th>
            {data.roles.map((r) => (
              <Th key={r.role} className="text-center">
                {ROLE_LABEL[r.role] || r.role}
              </Th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.permissions.map((p) => (
            <tr key={p.permission}>
              <Td>
                <div className="mono text-xs font-semibold">{p.permission}</div>
                <div className="text-xs text-slate-500">{p.description}</div>
              </Td>
              {data.roles.map((r) => (
                <Td key={r.role} className="text-center">
                  {r.permissions.includes(p.permission) ? <span className="font-bold text-emerald-600" aria-label="allowed">✔</span> : <span className="text-slate-300" aria-label="not allowed">—</span>}
                </Td>
              ))}
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

/* ------------------------------------------------------------------ Credentials */
function CredentialsTab() {
  const { data, error, loading, reload } = useLoader(() => api.get<Credential[]>("/api/credentials"));
  const [editing, setEditing] = useState<Credential | "new" | null>(null);
  const [form, setForm] = useState({ name: "", username: "", password: "", description: "" });
  const [formError, setFormError] = useState<unknown>(null);

  function open(c: Credential | "new") {
    setFormError(null);
    setEditing(c);
    setForm(c === "new" ? { name: "", username: "", password: "", description: "" } : { name: c.name, username: c.username, password: "", description: c.description });
  }

  async function submit() {
    setFormError(null);
    try {
      if (editing === "new") await api.post("/api/credentials", form);
      else if (editing) await api.patch(`/api/credentials/${editing.id}`, { name: form.name, username: form.username, description: form.description, ...(form.password ? { password: form.password } : {}) });
      setEditing(null);
      reload();
    } catch (e) {
      setFormError(e);
    }
  }

  async function remove(c: Credential) {
    if (!confirm(`Delete credential ${c.name}?`)) return;
    try {
      await api.del(`/api/credentials/${c.id}`);
      reload();
    } catch (e) {
      setFormError(e);
    }
  }

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  return (
    <Card
      title="SSH credentials"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />} onClick={() => open("new")}>
          Add credential
        </Button>
      }
    >
      <div className="px-4 pt-3 text-xs text-slate-500">Passwords are encrypted at rest (Fernet) and are never displayed, returned by the API or written to logs.</div>
      <div className="px-4 pt-3 empty:hidden">
        <ErrorBanner error={!editing ? formError : null} />
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Name</Th>
            <Th>Username</Th>
            <Th>Password</Th>
            <Th>Used by</Th>
            <Th>Updated</Th>
            <Th />
          </tr>
        </thead>
        <tbody>
          {data?.map((c) => (
            <tr key={c.id}>
              <Td className="font-medium">{c.name}</Td>
              <Td mono>{c.username}</Td>
              <Td mono className="text-slate-400">••••••••</Td>
              <Td>{c.switch_count} switches</Td>
              <Td className="text-slate-500">{fmtRelative(c.updated_at)}</Td>
              <Td className="text-right">
                <Button size="sm" variant="ghost" onClick={() => open(c)}>
                  Edit
                </Button>
                <Button size="sm" variant="ghost" icon={<Trash2 className="h-3.5 w-3.5" />} onClick={() => remove(c)} disabled={c.switch_count > 0}>
                  Delete
                </Button>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "Add credential" : `Edit ${form.name}`}
        footer={
          <>
            <Button onClick={() => setEditing(null)}>Cancel</Button>
            <Button variant="primary" onClick={submit}>
              Save
            </Button>
          </>
        }
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name">
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </Field>
          <Field label="SSH username">
            <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="off" />
          </Field>
          <Field label={editing === "new" ? "SSH password" : "New SSH password (leave empty to keep)"}>
            <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="new-password" />
          </Field>
          <Field label="Description">
            <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </Field>
          <div className="sm:col-span-2">
            <ErrorBanner error={formError} />
          </div>
        </div>
      </Modal>
    </Card>
  );
}

/* ------------------------------------------------------------------ Account */
function AccountTab() {
  const { user } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [ok, setOk] = useState(false);

  async function submit() {
    setError(null);
    setOk(false);
    try {
      await api.post("/api/auth/change-password", { current_password: current, new_password: next });
      setOk(true);
      setCurrent("");
      setNext("");
    } catch (e) {
      setError(e);
    }
  }

  return (
    <Card title={`Signed in as ${user?.username} (${user?.role})`} className="max-w-xl">
      <div className="space-y-4">
        <Field label="Current password">
          <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" hint="12+ characters, 3 of: lower, upper, digit, symbol. Other sessions are signed out.">
          <Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <ErrorBanner error={error} />
        {ok && <Notice tone="green">Password changed.</Notice>}
        <Button variant="primary" onClick={submit} disabled={!current || !next}>
          Change password
        </Button>
      </div>
    </Card>
  );
}
