import { AlertTriangle, Bell, CheckCircle2, Layers, Power, Search, Server, Siren, WifiOff, XCircle } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { AlertItem, AlertSummary, SafetyResponse } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { MacSearchBox } from "../components/MacSearchBox";
import { SafetyIndicatorBlock } from "../components/SafetyIndicator";
import { ActionStatusBadge, Badge, Card, ClassBadge, EmptyState, ErrorBanner, Loading, PageHeader, SeverityBadge, StatCard, SwitchStatusBadge, Table, Td, Th, cx } from "../components/ui";
import { fmtRelative } from "../lib/format";
import { useInterval, useLoader } from "../lib/hooks";

interface Dashboard {
  stats: {
    total_switches: number;
    enabled_switches: number;
    online: number;
    offline: number;
    unknown: number;
    aos_versions: Record<string, number>;
    searches_today: number;
    macs_found_today: number;
    failed_ssh_today: number;
    port_actions_today: number;
  };
  recent_searches: { id: string; mac: string; user: string; status: string; found: number; created_at: string; likely_edge: { switch_name: string; port: string; vlan_id: number | null } | null }[];
  recent_actions: { id: number; switch_name: string; port: string; mac: string; status: string; dry_run: boolean; user: string; created_at: string; classification: string }[];
  connectivity: { id: number; name: string; host: string; status: string; enabled: boolean; last_check_at: string | null; last_error: string; model: string; aos_version: string }[];
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data, error, loading, reload } = useLoader(() => api.get<Dashboard>("/api/dashboard"));
  const safety = useLoader(() => api.get<SafetyResponse>("/api/safety"));
  const alerts = useLoader(() =>
    can("view_alerts")
      ? Promise.all([api.get<AlertSummary>("/api/alerts/summary"), api.get<{ items: AlertItem[] }>("/api/alerts", { status: "open", limit: 6 })])
      : Promise.resolve(null),
  );
  useInterval(() => {
    reload(true);
    safety.reload(true);
    alerts.reload(true);
  }, 30000);

  if (loading && !data) return <Loading />;
  if (error && !data) return <ErrorBanner error={error} onRetry={() => reload()} />;
  if (!data) return null;
  const s = data.stats;

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Switch inventory health and today's activity" />
      <Card className="mb-6">
        <MacSearchBox onStarted={(id) => navigate(`/mac-search/${id}`)} compact />
      </Card>

      <div className="mb-6 grid gap-6 xl:grid-cols-3">
        <Card title="Network safety">
          {safety.data ? (
            <>
              <SafetyIndicatorBlock indicator={safety.data.indicator} />
              <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
                <div>
                  <dt className="text-xs uppercase tracking-wide text-slate-500">Mode</dt>
                  <dd className="font-semibold">{safety.data.state.mode}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-slate-500">Dry run</dt>
                  <dd className="font-semibold">{safety.data.state.dry_run_mode ? "ON" : "off"}</dd>
                </div>
              </dl>
              {can("view_safety") && (
                <Link className="mt-3 inline-block text-xs font-medium text-teal-700 hover:underline dark:text-teal-400" to="/safety">
                  Safety controls →
                </Link>
              )}
            </>
          ) : (
            <Loading />
          )}
        </Card>
        <Card title={<span className="flex items-center gap-2"><Siren className="h-4 w-4" /> Circuit breaker</span>}>
          {safety.data ? (
            <>
              <div className={cx("text-lg font-semibold", safety.data.state.safe_mode ? "text-red-600" : "text-emerald-700 dark:text-emerald-400")}>
                {safety.data.state.safe_mode ? "SAFE MODE" : "Closed"}
              </div>
              {safety.data.state.safe_mode && <p className="text-sm text-red-700 dark:text-red-300">{safety.data.state.safe_mode_reason}</p>}
              <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
                {(
                  [
                    ["SSH failures", safety.data.breaker.ssh_failures],
                    ["Auth failures", safety.data.breaker.auth_failures],
                    ["Validation failures", safety.data.breaker.validation_failures],
                    ["Unexpected output", safety.data.breaker.unexpected_output],
                  ] as const
                ).map(([k, n]) => (
                  <div key={k}>
                    <dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt>
                    <dd className="tnum font-semibold">{n}</dd>
                  </div>
                ))}
              </dl>
            </>
          ) : (
            <Loading />
          )}
        </Card>
        <Card
          title={<span className="flex items-center gap-2"><Bell className="h-4 w-4" /> Open alerts {alerts.data ? `(${alerts.data[0].open})` : ""}</span>}
          actions={can("view_alerts") && <Link className="text-xs font-medium text-teal-700 hover:underline dark:text-teal-400" to="/alerts">All alerts →</Link>}
          padded={false}
        >
          {!alerts.data || alerts.data[1].items.length === 0 ? (
            <EmptyState icon={<Bell className="h-6 w-6" />} title="No open alerts" />
          ) : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">
              {alerts.data[1].items.map((a) => (
                <li key={a.id} className="flex items-start gap-2 px-4 py-2.5 text-sm">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0">
                    <div className="truncate font-medium">{a.title}</div>
                    <div className="text-xs text-slate-500">{fmtRelative(a.last_seen_at)}{a.occurrences > 1 ? ` · ×${a.occurrences}` : ""}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 min-[1800px]:grid-cols-8">
        <StatCard label="Total switches" value={s.total_switches} icon={<Server className="h-4 w-4" />} hint={`${s.enabled_switches} enabled`} />
        <StatCard label="Online" value={s.online} tone="green" icon={<CheckCircle2 className="h-4 w-4" />} />
        <StatCard label="Offline / errors" value={s.offline} tone={s.offline ? "red" : "slate"} icon={<WifiOff className="h-4 w-4" />} hint={s.unknown ? `${s.unknown} not checked yet` : undefined} />
        <StatCard
          label="AOS versions"
          value={Object.keys(s.aos_versions).length}
          icon={<Layers className="h-4 w-4" />}
          hint={Object.entries(s.aos_versions)
            .map(([v, n]) => `${v}: ${n}`)
            .join(" · ")}
        />
        <StatCard label="Searches today" value={s.searches_today} tone="teal" icon={<Search className="h-4 w-4" />} />
        <StatCard label="MACs found today" value={s.macs_found_today} tone="green" icon={<CheckCircle2 className="h-4 w-4" />} />
        <StatCard label="Failed SSH today" value={s.failed_ssh_today} tone={s.failed_ssh_today ? "amber" : "slate"} icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Port actions today" value={s.port_actions_today} icon={<Power className="h-4 w-4" />} />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <Card title="Recent MAC searches" actions={<Link className="text-xs font-medium text-teal-700 hover:underline dark:text-teal-400" to="/history">All history →</Link>} padded={false}>
          {data.recent_searches.length === 0 ? (
            <EmptyState icon={<Search className="h-8 w-8" />} title="No searches yet" />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>MAC</Th>
                  <Th>Result</Th>
                  <Th>User</Th>
                  <Th>When</Th>
                </tr>
              </thead>
              <tbody>
                {data.recent_searches.map((r) => (
                  <tr key={r.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => navigate(`/mac-search/${r.id}`)}>
                    <Td mono>{r.mac}</Td>
                    <Td>
                      {r.status !== "completed" ? (
                        <Badge tone="blue">{r.status}</Badge>
                      ) : r.found ? (
                        <span className="text-sm">
                          <Badge tone="green">Found</Badge>{" "}
                          {r.likely_edge && (
                            <span className="mono text-xs text-slate-500">
                              {r.likely_edge.switch_name} {r.likely_edge.port}
                            </span>
                          )}
                        </span>
                      ) : (
                        <Badge>Not found</Badge>
                      )}
                    </Td>
                    <Td>{r.user}</Td>
                    <Td className="whitespace-nowrap text-slate-500">{fmtRelative(r.created_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>

        <Card title="Recent port actions" actions={<Link className="text-xs font-medium text-teal-700 hover:underline dark:text-teal-400" to="/port-actions">All actions →</Link>} padded={false}>
          {data.recent_actions.length === 0 ? (
            <EmptyState icon={<Power className="h-8 w-8" />} title="No port actions" />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Switch / port</Th>
                  <Th>Type</Th>
                  <Th>Status</Th>
                  <Th>User</Th>
                  <Th>When</Th>
                </tr>
              </thead>
              <tbody>
                {data.recent_actions.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <Td>
                      <span className="font-medium">{a.switch_name}</span> <span className="mono text-xs">{a.port}</span>
                    </Td>
                    <Td>
                      <ClassBadge value={a.classification} />
                    </Td>
                    <Td>
                      <ActionStatusBadge status={a.status} />
                    </Td>
                    <Td>{a.user}</Td>
                    <Td className="whitespace-nowrap text-slate-500">{fmtRelative(a.created_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>

      <Card title="Switch connectivity" className="mt-6" padded={false} actions={<Link className="text-xs font-medium text-teal-700 hover:underline dark:text-teal-400" to="/switches">Manage →</Link>}>
        {data.connectivity.length === 0 ? (
          <EmptyState icon={<Server className="h-8 w-8" />} title="No switches in the inventory">
            Add switches under <Link className="text-teal-700 underline" to="/switches">Switches</Link>.
          </EmptyState>
        ) : (
          <div className="grid gap-px bg-slate-200 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4 dark:bg-slate-800">
            {data.connectivity.map((c) => (
              <Link key={c.id} to={`/switches/${c.id}`} className="flex items-start justify-between gap-3 bg-white p-3 hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-800/60">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold">{c.name}</div>
                  <div className="mono truncate text-xs text-slate-500">
                    {c.host} · {c.model || "?"} · {c.aos_version || "AOS ?"}
                  </div>
                  {c.last_error && c.status !== "online" && (
                    <div className="mt-1 flex items-start gap-1 text-xs text-red-600 dark:text-red-400">
                      <XCircle className="mt-0.5 h-3 w-3 shrink-0" />
                      <span className="line-clamp-2">{c.last_error}</span>
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  {c.enabled ? <SwitchStatusBadge status={c.status} /> : <Badge>Disabled</Badge>}
                  <span className="text-[11px] text-slate-500">{fmtRelative(c.last_check_at)}</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
