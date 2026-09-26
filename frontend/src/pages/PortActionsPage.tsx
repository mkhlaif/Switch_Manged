import { Power } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { PortAction } from "../api/types";
import { ActionProgress, SafetyReportPanel } from "../components/RestartDialog";
import { ReasonList } from "../components/ResultDetails";
import { ActionStatusBadge, Badge, Card, ClassBadge, CodeBlock, EmptyState, ErrorBanner, KV, Loading, Modal, Notice, PageHeader, Select, Table, Td, Th } from "../components/ui";
import { fmtDateTime, formatMac } from "../lib/format";
import { useInterval, useLoader } from "../lib/hooks";
import { Pager } from "./HistoryPage";

const PAGE = 50;

export default function PortActionsPage() {
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<PortAction | null>(null);
  const { data, error, loading, reload } = useLoader(
    () => api.get<{ total: number; items: PortAction[] }>("/api/ports/actions", { status, limit: PAGE, offset }),
    [status, offset],
  );
  useInterval(() => reload(true), 5000, !!data?.items.some((a) => a.status === "running"));

  return (
    <>
      <PageHeader title="Port Actions" subtitle="Port restarts, dry runs and denied attempts" />
      <Card padded={false}>
        <div className="flex gap-3 border-b border-slate-200 p-3 dark:border-slate-800">
          <Select
            className="w-52"
            value={status}
            onChange={(e) => {
              setOffset(0);
              setStatus(e.target.value);
            }}
          >
            <option value="">All (except unconfirmed plans)</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
            <option value="dry_run">Dry run</option>
            <option value="denied">Denied</option>
            <option value="aborted">Aborted</option>
            <option value="running">Running</option>
            <option value="interrupted">Interrupted</option>
            <option value="planned">Planned (unconfirmed)</option>
            <option value="expired">Expired</option>
          </Select>
        </div>
        {error ? (
          <div className="p-4">
            <ErrorBanner error={error} onRetry={() => reload()} />
          </div>
        ) : loading && !data ? (
          <Loading />
        ) : !data?.items.length ? (
          <EmptyState icon={<Power className="h-8 w-8" />} title="No port actions" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>User</Th>
                  <Th>Switch</Th>
                  <Th>Port</Th>
                  <Th>MAC</Th>
                  <Th>Classification</Th>
                  <Th>Method</Th>
                  <Th>Status</Th>
                  <Th>Result</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => setSelected(a)}>
                    <Td className="whitespace-nowrap">{fmtDateTime(a.created_at)}</Td>
                    <Td>{a.requested_by}</Td>
                    <Td className="font-medium">{a.switch_name}</Td>
                    <Td mono>{a.port}</Td>
                    <Td mono>{formatMac(a.mac)}</Td>
                    <Td>
                      <ClassBadge value={a.classification} />
                    </Td>
                    <Td>{a.method === "poe_cycle" ? "PoE cycle" : "Link bounce"}</Td>
                    <Td>
                      <ActionStatusBadge status={a.status} />
                    </Td>
                    <Td className="max-w-md truncate text-sm text-slate-600 dark:text-slate-300">{a.error_message || a.blocked_reason || a.result_message}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={data.total} offset={offset} page={PAGE} onChange={setOffset} />
          </>
        )}
      </Card>
      {selected && <ActionDetail action={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function ActionDetail({ action, onClose }: { action: PortAction; onClose: () => void }) {
  return (
    <Modal open onClose={onClose} width="max-w-3xl" title={`Port action #${action.id} — ${action.switch_name} ${action.port}`}>
      <div className="space-y-5">
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <KV label="Status">
            <ActionStatusBadge status={action.status} />
          </KV>
          <KV label="Requested by">{action.requested_by}</KV>
          <KV label="Created">{fmtDateTime(action.created_at)}</KV>
          <KV label="Finished">{fmtDateTime(action.finished_at)}</KV>
          <KV label="Switch">{action.switch_name}</KV>
          <KV label="Port" mono>{action.port}</KV>
          <KV label="MAC" mono>{formatMac(action.mac)}</KV>
          <KV label="VLAN" mono>{action.vlan_id ?? "—"}</KV>
          <KV label="Classification">
            <ClassBadge value={action.classification} confidence={action.classification_confidence} />
          </KV>
          <KV label="Method">{action.method === "poe_cycle" ? "PoE power cycle" : "Link bounce"}</KV>
          <KV label="Strategy" mono>
            <span className="break-words text-[11px]">{action.strategy || "—"}</span>
          </KV>
          <KV label="Mode">{action.dry_run ? <Badge tone="blue">Dry run</Badge> : <Badge tone="red">Live</Badge>}</KV>
          {action.trunk_override && (
            <KV label="Trunk override">
              <Badge tone="red">Yes</Badge>
            </KV>
          )}
        </dl>
        {action.reason && (
          <div className="text-sm">
            <span className="font-medium">Reason:</span> {action.reason}
          </div>
        )}
        {action.blocked_reason && (
          <Notice tone="red" title="Blocked">
            {action.blocked_reason}
          </Notice>
        )}
        {action.status === "denied" && <SafetyReportPanel action={action} />}
        {action.commands.length > 0 && (
          <div>
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">Planned commands</div>
            <CodeBlock lines={action.commands} />
            <div className="mt-2 text-xs text-slate-500">
              Executed: {action.commands_executed.length ? action.commands_executed.join(" → ") : "none"}
            </div>
          </div>
        )}
        <ActionProgress action={action} />
        {action.classification_reasons.length > 0 && (
          <details className="text-sm">
            <summary className="cursor-pointer font-medium">Classification reasons</summary>
            <div className="mt-2">
              <ReasonList reasons={action.classification_reasons} />
            </div>
          </details>
        )}
        {action.search_id && (
          <Link className="text-sm text-teal-700 underline dark:text-teal-400" to={`/mac-search/${action.search_id}`}>
            Open originating search
          </Link>
        )}
      </div>
    </Modal>
  );
}
