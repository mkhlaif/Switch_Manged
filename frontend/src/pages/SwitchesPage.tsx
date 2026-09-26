import { Download, Plus, ScanSearch, Search, Server, Upload } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { DiscoveryJob, Switch } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useSafetyFlags } from "../components/Layout";
import { ImportDialog } from "../components/ImportDialog";
import { SwitchForm } from "../components/SwitchForm";
import {
  Badge,
  Button,
  Card,
  DiscoveryStatusBadge,
  EmptyState,
  ErrorBanner,
  Input,
  Loading,
  Notice,
  PageHeader,
  Select,
  SwitchStatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { fmtRelative } from "../lib/format";
import { useLoader } from "../lib/hooks";

export default function SwitchesPage() {
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const flags = useSafetyFlags();
  const { data, error, loading, reload } = useLoader(() => api.get<Switch[]>("/api/switches"));
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [adding, setAdding] = useState(false);
  const [importing, setImporting] = useState(false);
  const [discovery, setDiscovery] = useState("");
  const [job, setJob] = useState<DiscoveryJob | null>(null);
  const [jobError, setJobError] = useState<unknown>(null);

  useEffect(() => {
    if (!job || !["queued", "running"].includes(job.status)) return;
    const timer = window.setTimeout(async () => {
      try {
        const next = await api.get<DiscoveryJob>(`/api/discovery/jobs/${job.id}`);
        setJob(next);
        if (!["queued", "running"].includes(next.status)) reload(true);
      } catch (e) {
        setJobError(e);
      }
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [job, reload]);

  async function discoverAll() {
    setJobError(null);
    try {
      setJob(await api.post<DiscoveryJob>("/api/discovery/jobs", { all_enabled: true }));
    } catch (e) {
      setJobError(e);
    }
  }
  const exportClass =
    "inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 text-sm font-medium text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800";

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data || []).filter(
      (s) =>
        (!status || s.status === status) &&
        (!discovery || s.discovery_status === discovery) &&
        (!needle || [s.name, s.host, s.hostname, s.model, s.aos_version, s.site, s.location].some((v) => (v || "").toLowerCase().includes(needle))),
    );
  }, [data, q, status, discovery]);

  return (
    <>
      <PageHeader
        title="Switches"
        subtitle="Alcatel-Lucent Enterprise OmniSwitch inventory"
        actions={
          hasRole("admin") && (
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" icon={<Plus className="h-4 w-4" />} onClick={() => setAdding(true)}>
                Add switch
              </Button>
              <Button icon={<Upload className="h-4 w-4" />} onClick={() => setImporting(true)}>
                Import
              </Button>
              <Button
                icon={<ScanSearch className="h-4 w-4" />}
                loading={!!job && ["queued", "running"].includes(job.status)}
                onClick={discoverAll}
              >
                Discover all
              </Button>
              <a className={exportClass} href="/api/switches/export?format=csv" download>
                <Download className="h-4 w-4" /> Export CSV
              </a>
              <a className={exportClass} href="/api/switches/export?format=json" download>
                <Download className="h-4 w-4" /> Export JSON
              </a>
            </div>
          )
        }
      />
      <ErrorBanner error={jobError} />
      {job && (
        <div className="mb-4">
          <Notice
            tone={job.status === "completed" && !job.failed && !job.mismatched ? "green" : ["queued", "running"].includes(job.status) ? "blue" : "amber"}
            title={`Discovery ${job.status}: ${job.processed}/${job.total}`}
          >
            {job.discovered} discovered · {job.mismatched} identity mismatch · {job.failed} failed. Only the read-only discovery command is used.
            {job.error && <div className="mt-1">{job.error}</div>}
          </Notice>
        </div>
      )}
      <Card padded={false}>
        <div className="flex flex-wrap gap-3 border-b border-slate-200 p-3 dark:border-slate-800">
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-slate-400" />
            <Input className="pl-9" placeholder="Filter by name, IP, model, AOS, site, location…" aria-label="Filter switches" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <Select className="w-44" aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="auth_failed">Auth failed</option>
            <option value="hostkey_error">Host key</option>
            <option value="error">Error</option>
            <option value="unknown">Not checked</option>
          </Select>
          <Select className="w-48" aria-label="Filter by discovery" value={discovery} onChange={(e) => setDiscovery(e.target.value)}>
            <option value="">All identities</option>
            <option value="discovered">Discovered</option>
            <option value="not_discovered">Not discovered</option>
            <option value="discovery_failed">Discovery failed</option>
            <option value="mismatch">Identity mismatch</option>
          </Select>
        </div>
        {error ? (
          <div className="p-4">
            <ErrorBanner error={error} onRetry={() => reload()} />
          </div>
        ) : loading && !data ? (
          <Loading />
        ) : rows.length === 0 ? (
          <EmptyState icon={<Server className="h-8 w-8" />} title={data?.length ? "No switches match the filter" : "No switches yet"} />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Status</Th>
                <Th>Name</Th>
                <Th>Management IP</Th>
                <Th>Identity</Th>
                <Th>Model</Th>
                <Th>AOS</Th>
                <Th>Profile</Th>
                <Th>Role</Th>
                <Th>Site / location</Th>
                <Th>Host key</Th>
                <Th>Last check</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => navigate(`/switches/${s.id}`)}>
                  <Td>{s.enabled ? <SwitchStatusBadge status={s.status} /> : <Badge>Disabled</Badge>}</Td>
                  <Td className="font-medium">{s.name}</Td>
                  <Td mono>
                    {s.host}
                    {s.ssh_port !== 22 && `:${s.ssh_port}`}
                  </Td>
                  <Td>
                    <DiscoveryStatusBadge status={s.discovery_status} />
                  </Td>
                  <Td>{s.model || <span className="text-slate-400">—</span>}</Td>
                  <Td mono>{s.aos_version || <span className="font-sans text-slate-400">—</span>}</Td>
                  <Td>{s.effective_profile ? <Badge tone="teal">{s.effective_profile}</Badge> : <Badge tone="violet" className="max-w-40 truncate">none</Badge>}</Td>
                  <Td className="capitalize">{s.role}</Td>
                  <Td>{[s.site, s.location].filter(Boolean).join(" — ")}</Td>
                  <Td>{s.transport === "simulator" ? <Badge tone="violet">sim</Badge> : s.host_key_trusted ? <Badge tone="green">trusted</Badge> : <Badge tone="orange">not enrolled</Badge>}</Td>
                  <Td className="whitespace-nowrap text-slate-500">{fmtRelative(s.last_check_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={() => reload()} />}
      {adding && (
        <SwitchForm
          labMode={!!flags?.lab}
          onClose={() => setAdding(false)}
          onSaved={(s) => {
            setAdding(false);
            navigate(`/switches/${s.id}`);
          }}
        />
      )}
    </>
  );
}
