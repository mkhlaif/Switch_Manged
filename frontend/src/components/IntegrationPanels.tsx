import { Activity, Database } from "lucide-react";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { Mismatch, NetBoxDevice, ZabbixProblem } from "../api/types";
import { fmtDateTime } from "../lib/format";
import { Badge, Button, Card, ErrorBanner, KV, Notice } from "./ui";

function NotConfigured({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.code === "INTEGRATION_NOT_CONFIGURED") {
    return <Notice tone="blue">{error.message}</Notice>;
  }
  return <ErrorBanner error={error} />;
}

/** §18 NetBox reconciliation for one switch (read-only; nothing is written to NetBox). */
export function NetBoxPanel({ switchId }: { switchId: number }) {
  const [data, setData] = useState<{ netbox: NetBoxDevice | null; mismatches: Mismatch[] } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setData(await api.get(`/api/integrations/netbox/switches/${switchId}`));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title={<span className="flex items-center gap-2"><Database className="h-4 w-4" /> NetBox</span>}
      actions={
        <Button size="sm" loading={busy} onClick={load}>
          {data ? "Re-compare" : "Compare with NetBox"}
        </Button>
      }
    >
      {error ? (
        <NotConfigured error={error} />
      ) : !data ? (
        <p className="text-sm text-slate-500">Compares the inventory with NetBox (read-only). Differences are reported, never corrected automatically.</p>
      ) : (
        <div className="space-y-3">
          {data.netbox && (
            <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
              <KV label="Model">{data.netbox.model || "—"}</KV>
              <KV label="Role">{data.netbox.role || "—"}</KV>
              <KV label="Site">{data.netbox.site || "—"}</KV>
              <KV label="Status">{data.netbox.status || "—"}</KV>
              <KV label="Primary IP" mono>{data.netbox.primary_ip || "—"}</KV>
            </dl>
          )}
          {data.mismatches.length === 0 ? (
            <Badge tone="green">Inventory matches NetBox</Badge>
          ) : (
            <ul className="space-y-1 text-sm">
              {data.mismatches.map((m) => (
                <li key={m.field} className="text-amber-800 dark:text-amber-300">
                  <strong>{m.field}</strong>: {m.message} (inventory <span className="mono">{String(m.inventory ?? "—")}</span>, NetBox <span className="mono">{String(m.netbox ?? "—")}</span>)
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}

/** §19 Zabbix monitoring state for one switch (read-only). */
export function ZabbixPanel({ switchId }: { switchId: number }) {
  const [data, setData] = useState<{ host: { hostid: string; name: string; monitored: boolean } | null; problems: ZabbixProblem[] } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setData(await api.get(`/api/integrations/zabbix/switches/${switchId}`));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title={<span className="flex items-center gap-2"><Activity className="h-4 w-4" /> Zabbix</span>}
      actions={
        <Button size="sm" loading={busy} onClick={load}>
          {data ? "Refresh" : "Load problems"}
        </Button>
      }
    >
      {error ? (
        <NotConfigured error={error} />
      ) : !data ? (
        <p className="text-sm text-slate-500">Shows the monitoring state and current problems of this switch (read-only).</p>
      ) : !data.host ? (
        <p className="text-sm text-slate-500">No Zabbix host with this name.</p>
      ) : (
        <div className="space-y-2 text-sm">
          <div>
            Host <strong>{data.host.name}</strong> {data.host.monitored ? <Badge tone="green">monitored</Badge> : <Badge>not monitored</Badge>}
          </div>
          {data.problems.length === 0 ? (
            <Badge tone="green">No current problems</Badge>
          ) : (
            <ul className="space-y-1">
              {data.problems.map((p) => (
                <li key={p.eventid}>
                  <Badge tone={p.severity === "Disaster" || p.severity === "High" ? "red" : "amber"}>{p.severity}</Badge> {p.name}{" "}
                  <span className="text-xs text-slate-500">{fmtDateTime(new Date(Number(p.clock) * 1000).toISOString())}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}
