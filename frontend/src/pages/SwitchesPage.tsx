import { Plus, Search, Server } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { Switch } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useSafetyFlags } from "../components/Layout";
import { SwitchForm } from "../components/SwitchForm";
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Loading, PageHeader, Select, SwitchStatusBadge, Table, Td, Th } from "../components/ui";
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

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data || []).filter(
      (s) =>
        (!status || s.status === status) &&
        (!needle || [s.name, s.host, s.model, s.aos_version, s.location].some((v) => v.toLowerCase().includes(needle))),
    );
  }, [data, q, status]);

  return (
    <>
      <PageHeader
        title="Switches"
        subtitle="Alcatel-Lucent Enterprise OmniSwitch inventory"
        actions={
          hasRole("admin") && (
            <Button variant="primary" icon={<Plus className="h-4 w-4" />} onClick={() => setAdding(true)}>
              Add switch
            </Button>
          )
        }
      />
      <Card padded={false}>
        <div className="flex flex-wrap gap-3 border-b border-slate-200 p-3 dark:border-slate-800">
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-slate-400" />
            <Input className="pl-9" placeholder="Filter by name, IP, model, AOS, location…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <Select className="w-44" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="auth_failed">Auth failed</option>
            <option value="hostkey_error">Host key</option>
            <option value="error">Error</option>
            <option value="unknown">Not checked</option>
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
                <Th>Model</Th>
                <Th>AOS</Th>
                <Th>Profile</Th>
                <Th>Location</Th>
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
                  <Td>{s.model || <span className="text-slate-400">unknown</span>}</Td>
                  <Td mono>{s.aos_version || <span className="font-sans text-slate-400">unknown</span>}</Td>
                  <Td>{s.effective_profile ? <Badge tone="teal">{s.effective_profile}</Badge> : <Badge tone="violet" className="max-w-40 truncate">none</Badge>}</Td>
                  <Td>{s.location}</Td>
                  <Td>{s.transport === "simulator" ? <Badge tone="violet">sim</Badge> : s.host_key_trusted ? <Badge tone="green">trusted</Badge> : <Badge tone="orange">not enrolled</Badge>}</Td>
                  <Td className="whitespace-nowrap text-slate-500">{fmtRelative(s.last_check_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
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
