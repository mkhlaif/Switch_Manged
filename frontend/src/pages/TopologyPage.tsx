import { ArrowLeftRight, Network } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, EmptyState, ErrorBanner, Loading, PageHeader, SwitchStatusBadge, Table, Td, Th } from "../components/ui";
import { fmtRelative } from "../lib/format";
import { useLoader } from "../lib/hooks";

interface TopologyNode {
  id: number;
  name: string;
  role: string;
  model: string;
  aos_version: string;
  status: string;
  enabled: boolean;
  location: string;
  uplink_ports: string[];
}

interface TopologyLink {
  a: string;
  a_port: string;
  b: string;
  b_port: string;
  observed_at: string;
  source: string;
}

const COLUMNS = [
  { role: "core", title: "Core" },
  { role: "distribution", title: "Distribution" },
  { role: "access", title: "Access" },
  { role: "unknown", title: "Role not set" },
];

export default function TopologyPage() {
  const { data, error, loading, reload } = useLoader(() => api.get<{ nodes: TopologyNode[]; links: TopologyLink[]; note: string }>("/api/topology"));

  return (
    <>
      <PageHeader title="Topology" subtitle="Switches by topology role and the inter-switch links seen by LLDP. Read-only: building this view sends no command." />
      <ErrorBanner error={error} onRetry={() => reload()} />
      {loading && !data ? (
        <Loading />
      ) : data && data.nodes.length === 0 ? (
        <Card>
          <EmptyState icon={<Network className="h-8 w-8" />} title="No switches in the inventory" />
        </Card>
      ) : data ? (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {COLUMNS.map((col) => {
              const nodes = data.nodes.filter((n) => (n.role || "unknown") === col.role);
              return (
                <Card key={col.role} title={`${col.title} (${nodes.length})`} padded={false}>
                  {nodes.length === 0 ? (
                    <p className="p-4 text-sm text-slate-500">None</p>
                  ) : (
                    <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                      {nodes.map((n) => (
                        <li key={n.id} className="px-4 py-2.5">
                          <div className="flex items-center justify-between gap-2">
                            <Link to={`/switches/${n.id}`} className="truncate font-medium text-teal-700 hover:underline dark:text-teal-400">
                              {n.name}
                            </Link>
                            <SwitchStatusBadge status={n.status} />
                          </div>
                          <div className="mono truncate text-xs text-slate-500">
                            {n.model || "model ?"} · AOS {n.aos_version || "?"}
                          </div>
                          {n.uplink_ports.length > 0 && <div className="text-xs text-slate-500">Uplinks: {n.uplink_ports.join(", ")}</div>}
                          {!n.enabled && <Badge className="mt-1">disabled</Badge>}
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
              );
            })}
          </div>

          <Card title={<span className="flex items-center gap-2"><ArrowLeftRight className="h-4 w-4" /> Inter-switch links (LLDP)</span>} padded={false}>
            {data.links.length === 0 ? (
              <EmptyState title="No link observed yet">Links appear after searches or port queries have recorded LLDP neighbors that are switches in the inventory.</EmptyState>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Switch</Th>
                    <Th>Port</Th>
                    <Th>Neighbor switch</Th>
                    <Th>Neighbor port</Th>
                    <Th>Observed</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.links.map((l) => (
                    <tr key={`${l.a}-${l.a_port}-${l.b}`}>
                      <Td className="font-medium">{l.a}</Td>
                      <Td mono>{l.a_port}</Td>
                      <Td className="font-medium">{l.b}</Td>
                      <Td mono>{l.b_port || "—"}</Td>
                      <Td className="text-slate-500">{fmtRelative(l.observed_at)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
            <p className="px-4 py-3 text-xs text-slate-500">{data.note}</p>
          </Card>
        </div>
      ) : null}
    </>
  );
}
