import { Bell, Check } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { AlertItem } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Badge, Button, Card, EmptyState, ErrorBanner, Loading, PageHeader, Select, SeverityBadge, Table, Td, Th } from "../components/ui";
import { fmtDateTime, fmtRelative, formatMac } from "../lib/format";
import { useInterval, useLoader } from "../lib/hooks";

const KINDS = [
  "MULTIPLE_LOCATIONS",
  "MAC_MOVE",
  "UNEXPECTED_TRUNK",
  "NETBOX_MISMATCH",
  "SSH_FAILURE",
  "CIRCUIT_BREAKER",
  "BLOCKED_OPERATION",
  "RESTART_FAILED",
  "MAC_NOT_RETURNED",
  "UNEXPECTED_OUTPUT",
  "KILL_SWITCH",
  "EMERGENCY_MODE",
];

export default function AlertsPage() {
  const { can } = useAuth();
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [kind, setKind] = useState("");
  const [error, setError] = useState<unknown>(null);
  const { data, loading, reload, error: loadError } = useLoader(
    () => api.get<{ total: number; items: AlertItem[] }>("/api/alerts", { status, severity, kind, limit: 200 }),
    [status, severity, kind],
  );
  useInterval(() => reload(true), 20000);

  async function ack(a: AlertItem) {
    setError(null);
    try {
      await api.post(`/api/alerts/${a.id}/ack`);
      reload(true);
    } catch (e) {
      setError(e);
    }
  }

  return (
    <>
      <PageHeader title="Alerts" subtitle="Informational only: nothing acts on an alert automatically. Facts and evidence are shown; a human decides." />
      <ErrorBanner error={error || loadError} />
      <Card
        padded={false}
        title={`${data?.total ?? 0} alert(s)`}
        actions={
          <div className="flex flex-wrap gap-2">
            <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="">All</option>
            </Select>
            <Select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
              <option value="">All severities</option>
              {["CRITICAL", "HIGH", "WARNING", "INFO"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </Select>
            <Select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind">
              <option value="">All kinds</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k.replace(/_/g, " ").toLowerCase()}
                </option>
              ))}
            </Select>
          </div>
        }
      >
        {loading && !data ? (
          <Loading />
        ) : !data?.items.length ? (
          <EmptyState icon={<Bell className="h-8 w-8" />} title="No alerts">
            Multiple locations, MAC moves, undeclared trunks, NetBox mismatches, SSH failures, breaker trips, blocked operations and failed restarts appear here.
          </EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Severity</Th>
                <Th>Alert</Th>
                <Th>Where</Th>
                <Th>Seen</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id}>
                  <Td>
                    <SeverityBadge severity={a.severity} />
                  </Td>
                  <Td>
                    <div className="font-medium">{a.title}</div>
                    <div className="text-xs text-slate-500">{a.message}</div>
                    <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-400">{a.kind.replace(/_/g, " ")}</div>
                  </Td>
                  <Td className="text-xs">
                    {a.switch_name && (
                      <div>
                        {a.switch_name} {a.port && <span className="mono">{a.port}</span>}
                      </div>
                    )}
                    {a.mac && <div className="mono">{formatMac(a.mac)}</div>}
                    {typeof a.details.search_id === "string" && (
                      <Link className="text-teal-700 hover:underline dark:text-teal-400" to={`/mac-search/${a.details.search_id}`}>
                        open search
                      </Link>
                    )}
                  </Td>
                  <Td className="whitespace-nowrap text-xs text-slate-500">
                    <div title={fmtDateTime(a.last_seen_at)}>{fmtRelative(a.last_seen_at)}</div>
                    {a.occurrences > 1 && <Badge className="mt-1">×{a.occurrences}</Badge>}
                  </Td>
                  <Td className="text-xs">
                    {a.status === "open" ? <Badge tone="amber">open</Badge> : <span className="text-slate-500">ack by {a.acknowledged_by}</span>}
                  </Td>
                  <Td className="text-right">
                    {a.status === "open" && can("ack_alerts") && (
                      <Button size="sm" variant="ghost" icon={<Check className="h-3.5 w-3.5" />} onClick={() => ack(a)}>
                        Acknowledge
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
