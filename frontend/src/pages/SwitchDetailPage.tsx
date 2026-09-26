import { ArrowLeft, CheckCircle2, Fingerprint, KeyRound, Pencil, PlugZap, ScanSearch, ShieldAlert, Trash2, XCircle } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { DiscoveryOutcome, Switch } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useSafetyFlags } from "../components/Layout";
import { SwitchForm } from "../components/SwitchForm";
import { NetBoxPanel, ZabbixPanel } from "../components/IntegrationPanels";
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  DiscoveryStatusBadge,
  ErrorBanner,
  Field,
  Input,
  KV,
  Loading,
  Modal,
  Notice,
  PageHeader,
  SwitchStatusBadge,
} from "../components/ui";
import { fmtDateTime, fmtDuration } from "../lib/format";
import { useLoader } from "../lib/hooks";

interface TestResult {
  ok: boolean;
  status: string;
  title?: string;
  reason?: string;
  duration_ms: number;
  model?: string;
  version?: string;
  system_name?: string;
  commands?: string[];
}

export default function SwitchDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { hasRole, can } = useAuth();
  const [portQuery, setPortQuery] = useState("");
  const flags = useSafetyFlags();
  const { data: sw, setData, error, loading, reload } = useLoader(() => api.get<Switch>(`/api/switches/${id}`), [id]);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<TestResult | null>(null);
  const [discovery, setDiscovery] = useState<DiscoveryOutcome | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [acceptReason, setAcceptReason] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [editing, setEditing] = useState(false);
  const [hostKey, setHostKey] = useState<{ host_key: string; fingerprint: string; key_type: string; matches_trusted: boolean } | null>(null);
  const [confirmFp, setConfirmFp] = useState("");
  const [deleting, setDeleting] = useState(false);

  if (loading && !sw) return <Loading />;
  if (error && !sw) return <ErrorBanner error={error} onRetry={() => reload()} />;
  if (!sw) return null;

  async function run(kind: "test" | "discover") {
    setBusy(kind);
    setActionError(null);
    setResult(null);
    setDiscovery(null);
    try {
      if (kind === "test") setResult(await api.post<TestResult>(`/api/switches/${sw!.id}/test`));
      else setDiscovery(await api.post<DiscoveryOutcome>(`/api/switches/${sw!.id}/discover`));
      reload(true);
    } catch (e) {
      setActionError(e);
    } finally {
      setBusy(null);
    }
  }

  async function acceptIdentity() {
    setBusy("accept");
    setActionError(null);
    try {
      setData(await api.post<Switch>(`/api/switches/${sw!.id}/discovery/accept`, { reason: acceptReason.trim() }));
      setAccepting(false);
      setAcceptReason("");
      setDiscovery(null);
    } catch (e) {
      setActionError(e);
    } finally {
      setBusy(null);
    }
  }

  async function fetchKey() {
    setBusy("key");
    setActionError(null);
    try {
      setHostKey(await api.post(`/api/switches/${sw!.id}/host-key/fetch`));
      setConfirmFp("");
    } catch (e) {
      setActionError(e);
    } finally {
      setBusy(null);
    }
  }

  async function trustKey() {
    setBusy("trust");
    setActionError(null);
    try {
      setData(await api.post<Switch>(`/api/switches/${sw!.id}/host-key/trust`, { fingerprint: hostKey!.fingerprint }));
      setHostKey(null);
    } catch (e) {
      setActionError(e);
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    setBusy("delete");
    try {
      await api.del(`/api/switches/${sw!.id}`);
      navigate("/switches");
    } catch (e) {
      setActionError(e);
      setBusy(null);
    }
  }

  return (
    <>
      <Link to="/switches" className="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800 dark:hover:text-slate-200">
        <ArrowLeft className="h-4 w-4" /> Switches
      </Link>
      <PageHeader
        title={sw.name}
        subtitle={
          <span className="mono">
            {sw.host}:{sw.ssh_port} · {sw.discovery_status === "not_discovered" ? "not discovered yet" : `${sw.model || "model unknown"} · AOS ${sw.aos_version || "unknown"}`}
          </span>
        }
        actions={
          <>
            {hasRole("operator") && (
              <Button icon={<PlugZap className="h-4 w-4" />} loading={busy === "test"} onClick={() => run("test")}>
                Test SSH connection
              </Button>
            )}
            {hasRole("admin") && (
              <>
                <Button icon={<ScanSearch className="h-4 w-4" />} loading={busy === "discover"} onClick={() => run("discover")}>
                  Run discovery
                </Button>
                <Button icon={<Pencil className="h-4 w-4" />} onClick={() => setEditing(true)}>
                  Edit
                </Button>
                <Button variant="ghost" icon={<Trash2 className="h-4 w-4" />} onClick={() => setDeleting(true)}>
                  Delete
                </Button>
              </>
            )}
          </>
        }
      />

      <div className="space-y-6">
        <ErrorBanner error={actionError} />
        {result &&
          (result.ok ? (
            <Notice tone="green" icon={<CheckCircle2 className="mt-0.5 h-5 w-5" />} title={`SSH OK (${fmtDuration(result.duration_ms)})`}>
              The switch answered {result.model || "?"} running AOS {result.version || "?"} (connection test only; the identity is stored by discovery).
              {result.commands && (
                <div className="mt-2">
                  <CodeBlock lines={result.commands} />
                </div>
              )}
            </Notice>
          ) : (
            <Notice tone="red" icon={<XCircle className="mt-0.5 h-5 w-5" />} title={result.title || "SSH CONNECTION FAILED"}>
              <div>
                <strong>Switch:</strong> {sw.name}
              </div>
              <div>
                <strong>Reason:</strong> {result.reason}
              </div>
              <div className="mt-2">
                <Button size="sm" onClick={() => run("test")}>
                  Retry
                </Button>
              </div>
            </Notice>
          ))}

        {discovery && (
          <Notice
            tone={discovery.ok ? "green" : discovery.status === "mismatch" ? "amber" : "red"}
            icon={discovery.ok ? <CheckCircle2 className="mt-0.5 h-5 w-5" /> : <ShieldAlert className="mt-0.5 h-5 w-5" />}
            title={discovery.ok ? "DEVICE DISCOVERED" : discovery.status === "mismatch" ? "IDENTITY MISMATCH" : "DISCOVERY FAILED"}
          >
            {discovery.model ? (
              <div>
                {discovery.vendor} {discovery.model} · AOS <span className="mono">{discovery.version}</span> · command profile:{" "}
                <strong>{discovery.profile || "none"}</strong>
              </div>
            ) : null}
            {discovery.reason && (
              <div>
                <strong>{discovery.category || "Reason"}:</strong> {discovery.reason}
              </div>
            )}
            {discovery.commands.length > 0 && (
              <div className="mt-2">
                <CodeBlock lines={discovery.commands} />
              </div>
            )}
          </Notice>
        )}

        <Card
          title={
            <span className="flex items-center gap-2">
              <Fingerprint className="h-4 w-4" /> Device identity (automatic discovery)
            </span>
          }
          actions={
            hasRole("admin") &&
            sw.discovery_status === "mismatch" && (
              <Button size="sm" variant="primary" onClick={() => setAccepting(true)}>
                Review and accept identity
              </Button>
            )
          }
        >
          {sw.discovery_status === "mismatch" && (
            <Notice tone="amber" title="State-changing operations are blocked">
              The device no longer matches the expected or previously discovered identity: {sw.discovery_error}. Read-only operations continue.
              An administrator must review the change (e.g. an AOS upgrade or a replaced switch) before any restart is possible.
            </Notice>
          )}
          {sw.discovery_status === "discovery_failed" && (
            <Notice tone="red" title={`Discovery failed${sw.discovery_category ? ` (${sw.discovery_category})` : ""}`}>
              {sw.discovery_error || "The device could not be identified."} No operation other than discovery is possible until it succeeds.
            </Notice>
          )}
          {sw.discovery_status === "not_discovered" && (
            <Notice tone="blue" title="Not discovered yet">
              {sw.discovery_error ||
                "Discovery runs automatically once the switch can be reached securely (trusted SSH host key or a fingerprint supplied out of band), or on the first search."}
            </Notice>
          )}
          <dl className="mt-4 grid grid-cols-2 gap-5 sm:grid-cols-4">
            <KV label="Status">
              <DiscoveryStatusBadge status={sw.discovery_status} />
            </KV>
            <KV label="Vendor">{sw.vendor === "ALE" ? "Alcatel-Lucent Enterprise" : sw.vendor || "—"}</KV>
            <KV label="Model">{sw.model || "—"}</KV>
            <KV label="AOS version" mono>{sw.aos_version || "—"}</KV>
            <KV label="Discovered">{fmtDateTime(sw.discovered_at)}</KV>
            <KV label="Discovery profile" mono>{sw.discovery_profile || "—"}</KV>
            <KV label="System name" mono>{sw.system_name || "—"}</KV>
            <KV label="Environment">
              <Badge tone={sw.environment === "production" ? "violet" : "slate"}>{sw.environment}</Badge>
            </KV>
            <KV label="Expected model">{sw.expected_model || "—"}</KV>
            <KV label="Expected AOS" mono>{sw.expected_aos_version || "—"}</KV>
            <KV label="Expected host key" mono>{sw.expected_host_key_fingerprint ? `…${sw.expected_host_key_fingerprint.slice(-12)}` : "—"}</KV>
            <KV label="Serial number">
              <span className="text-xs font-normal text-slate-500">not collected (no verified command)</span>
            </KV>
          </dl>
        </Card>

        <div className="grid gap-6 xl:grid-cols-3">
          <Card title="Switch" className="xl:col-span-2">
            <dl className="grid grid-cols-2 gap-5 sm:grid-cols-3">
              <KV label="Name">{sw.name}</KV>
              <KV label="IP / hostname" mono>{sw.host}</KV>
              <KV label="SSH port" mono>{sw.ssh_port}</KV>
              <KV label="Command profile">
                {sw.effective_profile ? <Badge tone="teal">{sw.effective_profile}</Badge> : <Badge tone="violet">none</Badge>}
                <div className="mt-1 text-xs font-normal text-slate-500">{sw.profile_reason}</div>
              </KV>
              <KV label="Hostname" mono>{sw.hostname || "—"}</KV>
              <KV label="Site">{sw.site || "—"}</KV>
              <KV label="Location">{sw.location || "—"}</KV>
              <KV label="Device locations (MAC operators)">
                {Object.keys(sw.port_locations || {}).length ? (
                  <span className="text-sm font-normal">
                    {Object.entries(sw.port_locations).map(([port, label]) => (
                      <span key={port} className="block">
                        <span className="mono">{port}</span> — {label}
                      </span>
                    ))}
                  </span>
                ) : (
                  "—"
                )}
              </KV>
              <KV label="Credential">{sw.credential_name || <span className="text-red-600">none assigned</span>}</KV>
              <KV label="Enabled">{sw.enabled ? "Yes" : "No"}</KV>
              <KV label="Uplink ports" mono>{sw.uplink_ports.length ? sw.uplink_ports.join(", ") : "—"}</KV>
              <KV label="Topology role">
                <Badge tone={sw.role === "core" || sw.role === "distribution" ? "violet" : "slate"}>{sw.role}</Badge>
              </KV>
              <KV label="Transport">{sw.transport === "simulator" ? "Simulator (lab)" : "SSH"}</KV>
              <KV label="Legacy SSH algorithms">{sw.legacy_ssh_algorithms ? "Enabled" : "Off"}</KV>
            </dl>
            {sw.description && <p className="mt-4 text-sm text-slate-600 dark:text-slate-300">{sw.description}</p>}
            {can("port_inspect") && (
              <form
                className="mt-5 flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4 dark:border-slate-800"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (portQuery.trim()) navigate(`/port?switch=${sw.id}&port=${encodeURIComponent(portQuery.trim())}`);
                }}
              >
                <Field label="Open port details (read-only)">
                  <Input className="mono w-40" value={portQuery} onChange={(e) => setPortQuery(e.target.value)} placeholder="1/1/24" />
                </Field>
                <Button type="submit" disabled={!portQuery.trim()}>
                  Open
                </Button>
              </form>
            )}
          </Card>

          <Card title="SSH status">
            <dl className="space-y-4">
              <KV label="Status">
                <SwitchStatusBadge status={sw.status} />
              </KV>
              <KV label="Last check">{fmtDateTime(sw.last_check_at)}</KV>
              <KV label="Last successful connection">{fmtDateTime(sw.last_success_at)}</KV>
              <KV label="Last error">{sw.last_error ? <span className="text-sm font-normal text-red-700 dark:text-red-400">{sw.last_error}</span> : "—"}</KV>
            </dl>
          </Card>
        </div>

        {can("view_integrations") && (
          <div className="grid gap-6 xl:grid-cols-2">
            <NetBoxPanel switchId={sw.id} />
            <ZabbixPanel switchId={sw.id} />
          </div>
        )}

        {sw.transport === "ssh" && (
          <Card
            title={
              <span className="flex items-center gap-2">
                <KeyRound className="h-4 w-4" /> SSH host key
              </span>
            }
            actions={
              hasRole("admin") && (
                <Button size="sm" loading={busy === "key"} onClick={fetchKey}>
                  Fetch host key
                </Button>
              )
            }
          >
            {sw.host_key_trusted ? (
              <div className="text-sm">
                Trusted fingerprint: <span className="mono font-medium">{sw.host_key_fingerprint}</span>
              </div>
            ) : (
              <Notice tone="amber" title="No trusted host key">
                The tool refuses to connect until an administrator enrolls this switch's host key. This protects the switch credentials against man-in-the-middle attacks.
              </Notice>
            )}
            {hostKey && (
              <div className="mt-4 space-y-3 rounded-lg border border-slate-200 p-4 dark:border-slate-800">
                <div className="text-sm">
                  The switch presented a <strong>{hostKey.key_type}</strong> key with fingerprint:
                  <div className="mono mt-1 rounded bg-slate-100 px-2 py-1.5 text-sm break-all dark:bg-slate-800">{hostKey.fingerprint}</div>
                </div>
                {sw.host_key_trusted && !hostKey.matches_trusted && (
                  <Notice tone="red" title="The key differs from the trusted key">
                    Only replace it if you know the switch was re-keyed or replaced.
                  </Notice>
                )}
                <p className="text-xs text-slate-500">Verify this fingerprint out-of-band (for example from the switch console) before trusting it. Type the last 8 characters to confirm.</p>
                <div className="flex flex-wrap items-end gap-3">
                  <Field label="Last 8 characters">
                    <Input className="mono w-40" value={confirmFp} onChange={(e) => setConfirmFp(e.target.value)} />
                  </Field>
                  <Button variant="primary" disabled={confirmFp !== hostKey.fingerprint.slice(-8)} loading={busy === "trust"} onClick={trustKey}>
                    Trust this key
                  </Button>
                  <Button variant="ghost" onClick={() => setHostKey(null)}>
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </Card>
        )}
      </div>

      {editing && (
        <SwitchForm
          existing={sw}
          labMode={!!flags?.lab}
          onClose={() => setEditing(false)}
          onSaved={(s) => {
            setData(s);
            setEditing(false);
          }}
        />
      )}
      <Modal
        open={accepting}
        onClose={() => setAccepting(false)}
        title={`Accept the discovered identity of ${sw.name}?`}
        footer={
          <>
            <Button onClick={() => setAccepting(false)}>Cancel</Button>
            <Button variant="primary" disabled={acceptReason.trim().length < 3} loading={busy === "accept"} onClick={acceptIdentity}>
              Accept identity
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <p>
            Discovered: <strong>{sw.model}</strong> · AOS <span className="mono">{sw.aos_version}</span>. Difference: {sw.discovery_error}
          </p>
          <p>
            Accepting makes this the expected identity. It is audited, and the identity is checked again on the switch before every restart.
            Command profiles still have to be verified for this model and AOS version.
          </p>
          <Field label="Reason (audited)">
            <Input value={acceptReason} onChange={(e) => setAcceptReason(e.target.value)} placeholder="AOS upgraded to 8.10R2 (change CHG-1234)" />
          </Field>
        </div>
      </Modal>
      <Modal
        open={deleting}
        onClose={() => setDeleting(false)}
        title={`Delete ${sw.name}?`}
        footer={
          <>
            <Button onClick={() => setDeleting(false)}>Cancel</Button>
            <Button variant="danger" loading={busy === "delete"} onClick={remove}>
              Delete switch
            </Button>
          </>
        }
      >
        <p className="text-sm">The switch is removed from the inventory. Search history and audit records are kept.</p>
      </Modal>
    </>
  );
}
