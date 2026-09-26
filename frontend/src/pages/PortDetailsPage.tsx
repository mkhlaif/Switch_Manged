// §42 Port details: a live, read-only view of one port. Refresh and Trace MAC are read-only;
// Restart Port is visually separated and still goes through the full restart pipeline.
import { ArrowLeft, Crosshair, ListTree, Power, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { LldpNeighbor, MacSearch, PortDetails, Reason, VlanMembership } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { RestartDialog } from "../components/RestartDialog";
import { ReasonList } from "../components/ResultDetails";
import { Badge, Button, Card, ClassBadge, EmptyState, ErrorBanner, KV, Loading, Notice, PageHeader, Table, Td, Th } from "../components/ui";
import { fmtSpeed, formatMac } from "../lib/format";
import { useLoader } from "../lib/hooks";

interface PortInfo {
  switch: { id: number; name: string; model: string; aos_version: string; role: string };
  port: string;
  profile: string;
  mac: string | null;
  mac_on_port: boolean | null;
  details: PortDetails | null;
  vlans: VlanMembership[];
  tagged_vlans: number[];
  untagged_vlan: number | null;
  lldp: LldpNeighbor[];
  mac_count: number | null;
  classification: { category: string; confidence: string; confidence_score: number; reasons: Reason[] } | null;
  warnings: string[];
  commands: string[];
}

interface PortMacs {
  macs: { mac: string; vlan_id: number | null; mac_type: string; valid?: boolean }[];
  mac_count: number;
}

const COUNTER_GROUPS: { title: string; match: RegExp }[] = [
  { title: "Errors", match: /err|crc|align|collision|runt|giant|fragment/ },
  { title: "Drops", match: /drop|discard|lost|overrun|underrun/ },
  { title: "Traffic", match: /byte|frame|packet|unicast|broadcast|multicast|octet/ },
];

function counters(d: PortDetails | null, match: RegExp) {
  const rows: { name: string; rx?: number; tx?: number }[] = [];
  const keys = new Set([...Object.keys(d?.rx || {}), ...Object.keys(d?.tx || {})]);
  for (const k of keys) {
    if (match.test(k)) rows.push({ name: k.replace(/_/g, " "), rx: d?.rx?.[k], tx: d?.tx?.[k] });
  }
  return rows;
}

export default function PortDetailsPage() {
  const [params] = useSearchParams();
  const switchId = Number(params.get("switch"));
  const port = params.get("port") || "";
  const mac = params.get("mac") || "";
  const navigate = useNavigate();
  const { can } = useAuth();
  const [restart, setRestart] = useState(false);
  const [macs, setMacs] = useState<PortMacs | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [tracing, setTracing] = useState(false);
  const { data, error, loading, reload } = useLoader(
    () => api.get<PortInfo>(`/api/switches/${switchId}/ports/${port}`, { mac: mac || undefined }),
    [switchId, port, mac],
  );

  async function loadMacs() {
    setActionError(null);
    try {
      setMacs(await api.post<PortMacs>("/api/operations", { operation: "GET_PORT_MACS", switch_id: switchId, port }));
    } catch (e) {
      setActionError(e);
    }
  }

  async function traceMac() {
    if (!mac) return;
    setTracing(true);
    setActionError(null);
    try {
      const s = await api.post<MacSearch>("/api/mac/search", { mac });
      navigate(`/mac-search/${s.id}`);
    } catch (e) {
      setActionError(e);
      setTracing(false);
    }
  }

  if (!switchId || !port) return <EmptyState title="No port selected">Open a port from a search result or a switch.</EmptyState>;
  const d = data?.details || null;
  const c = data?.classification;

  return (
    <>
      <PageHeader
        title={`${data?.switch.name ?? "Switch"} · ${port}`}
        subtitle={
          <Link to={`/switches/${switchId}`} className="inline-flex items-center gap-1 text-teal-700 hover:underline dark:text-teal-400">
            <ArrowLeft className="h-3.5 w-3.5" /> Switch details
          </Link>
        }
        actions={
          <>
            <Button icon={<RefreshCw className="h-4 w-4" />} onClick={() => reload()} loading={loading}>
              Refresh
            </Button>
            <Button icon={<Crosshair className="h-4 w-4" />} onClick={traceMac} disabled={!mac || !can("mac_search")} loading={tracing} title={mac ? `Search ${formatMac(mac)} on all switches` : "Open this page from a MAC search to trace a MAC"}>
              Trace MAC
            </Button>
          </>
        }
      />
      <ErrorBanner error={error || actionError} onRetry={error ? () => reload() : undefined} />
      {loading && !data ? (
        <Loading label={`Reading ${port} (read-only)…`} />
      ) : data ? (
        <div className="grid gap-6 xl:grid-cols-3">
          <div className="space-y-6 xl:col-span-2">
            <Card title="Port">
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <KV label="Switch">{data.switch.name}</KV>
                <KV label="Port" mono>{data.port}</KV>
                <KV label="Description">{d?.alias || "—"}</KV>
                <KV label="Switch role">{data.switch.role}</KV>
                <KV label="Admin state">{d?.admin_status || "—"}</KV>
                <KV label="Operational state">
                  <Badge tone={d?.oper_status === "up" ? "green" : "red"}>{(d?.oper_status || "unknown").toUpperCase()}</Badge>
                </KV>
                <KV label="Speed">{fmtSpeed(d?.speed_mbps)}</KV>
                <KV label="Duplex">{d?.duplex || "—"}</KV>
                <KV label="Untagged VLAN" mono>{data.untagged_vlan ?? "—"}</KV>
                <KV label="Tagged VLANs" mono>{data.tagged_vlans.length ? data.tagged_vlans.join(", ") : "none"}</KV>
                <KV label="MACs learned" mono>{data.mac_count ?? "—"}</KV>
                <KV label="Profile" mono>{data.profile}</KV>
              </dl>
              {data.mac && (
                <p className="mt-3 text-sm">
                  MAC <span className="mono">{formatMac(data.mac)}</span> is {data.mac_on_port ? <strong>learned on this port</strong> : <strong className="text-red-600">not learned on this port</strong>}.
                </p>
              )}
              {data.warnings.map((w) => (
                <Notice key={w} tone="amber">{w}</Notice>
              ))}
            </Card>

            <div className="grid gap-6 lg:grid-cols-3">
              {COUNTER_GROUPS.map((g) => {
                const rows = counters(d, g.match);
                return (
                  <Card key={g.title} title={g.title} padded={false}>
                    {rows.length === 0 ? (
                      <p className="p-4 text-xs text-slate-500">Not reported by this profile.</p>
                    ) : (
                      <Table>
                        <thead>
                          <tr>
                            <Th>Counter</Th>
                            <Th className="text-right">Rx</Th>
                            <Th className="text-right">Tx</Th>
                          </tr>
                        </thead>
                        <tbody>
                          {rows.map((r) => (
                            <tr key={r.name}>
                              <Td className="text-xs">{r.name}</Td>
                              <Td className="tnum text-right">{r.rx ?? "—"}</Td>
                              <Td className="tnum text-right">{r.tx ?? "—"}</Td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    )}
                  </Card>
                );
              })}
            </div>

            <Card title="VLANs" padded={false}>
              <Table>
                <thead>
                  <tr>
                    <Th>VLAN</Th>
                    <Th>Mode</Th>
                    <Th>Status</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.vlans.map((v) => (
                    <tr key={`${v.vlan_id}-${v.mode_raw}`}>
                      <Td mono>{v.vlan_id}</Td>
                      <Td>{v.tagged ? "tagged" : v.tagged === false ? "untagged" : v.mode_raw}</Td>
                      <Td>{v.status}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>

            <Card title="LLDP neighbors" padded={false}>
              {data.lldp.length === 0 ? (
                <p className="p-4 text-sm text-slate-500">No LLDP neighbor.</p>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>System</Th>
                      <Th>Port</Th>
                      <Th>Capabilities</Th>
                      <Th>Management IP</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.lldp.map((n, i) => (
                      <tr key={i}>
                        <Td>
                          <div className="font-medium">{n.system_name || n.chassis_id}</div>
                          <div className="text-xs text-slate-500">{n.system_description}</div>
                        </Td>
                        <Td mono>{n.port_id}</Td>
                        <Td>{n.capabilities.join(", ")}</Td>
                        <Td mono>{n.management_ip || "—"}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>

            <Card
              title="MACs on this port"
              actions={
                <Button size="sm" icon={<ListTree className="h-3.5 w-3.5" />} onClick={loadMacs}>
                  Load MACs
                </Button>
              }
              padded={false}
            >
              {!macs ? (
                <p className="p-4 text-sm text-slate-500">Read-only GET_PORT_MACS on request.</p>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>MAC</Th>
                      <Th>VLAN</Th>
                      <Th>Type</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {macs.macs.map((m) => (
                      <tr key={`${m.mac}-${m.vlan_id}`}>
                        <Td mono>{formatMac(m.mac)}</Td>
                        <Td mono>{m.vlan_id ?? "—"}</Td>
                        <Td>{m.mac_type}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
          </div>

          <div className="space-y-6">
            <Card title="Classification">
              {c ? (
                <>
                  <ClassBadge value={c.category} confidence={c.confidence} large />
                  <div className="mt-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence</div>
                  <ReasonList reasons={c.reasons} />
                </>
              ) : (
                <p className="text-sm text-slate-500">Not available.</p>
              )}
            </Card>

            {can("restart_port") && (
              <Card title={<span className="flex items-center gap-2 text-red-700 dark:text-red-400"><Power className="h-4 w-4" /> State-changing action</span>} className="border-red-300 dark:border-red-500/40">
                <p className="text-sm text-slate-600 dark:text-slate-300">
                  Restarting re-checks the port, requires the typed confirmation <span className="mono">RESTART PORT {data.port}</span>, runs only in MAINTENANCE mode and is fully audited. Trunk, uplink and uncertain ports are blocked.
                </p>
                <Button variant="danger" className="mt-4 w-full" icon={<Power className="h-4 w-4" />} disabled={!mac} onClick={() => setRestart(true)} title={mac ? "" : "A restart is always bound to the MAC that identifies the device"}>
                  Restart port…
                </Button>
                {!mac && <p className="mt-2 text-xs text-slate-500">Open this page from a MAC search result to restart: the restart is bound to the device's MAC.</p>}
              </Card>
            )}

            <Card title="Commands executed (read-only)">
              <ul className="space-y-1">
                {data.commands.map((cmd, i) => (
                  <li key={i} className="mono text-xs text-slate-600 dark:text-slate-300">{cmd}</li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      ) : null}
      {restart && data && <RestartDialog target={{ switchId, port: data.port, mac, switchName: data.switch.name }} onClose={() => setRestart(false)} />}
    </>
  );
}
