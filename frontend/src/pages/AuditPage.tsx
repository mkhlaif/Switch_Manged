import { Download, FileClock, TerminalSquare } from "lucide-react";
import { useState } from "react";
import { api, buildUrl } from "../api/client";
import type { AuditEntry, SshSessionItem } from "../api/types";
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Loading, Modal, PageHeader, Select, SeverityBadge, Table, Td, Th, cx } from "../components/ui";
import { fmtDateTime, formatMac } from "../lib/format";
import { useLoader } from "../lib/hooks";
import { Pager } from "./HistoryPage";

const PAGE = 100;

function resultTone(result: string) {
  return result === "SUCCESS" ? "green" : result === "FAILED" ? "red" : result === "DENIED" || result === "BLOCKED" ? "violet" : "slate";
}

export default function AuditPage() {
  const [tab, setTab] = useState<"audit" | "sessions">("audit");
  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Administrative actions, security events and every SSH session opened by the safety firewall" />
      <div className="mb-6 flex gap-1 border-b border-slate-200 dark:border-slate-800">
        {([
          ["audit", "Audit & security events", <FileClock key="a" className="h-4 w-4" />],
          ["sessions", "SSH sessions", <TerminalSquare key="s" className="h-4 w-4" />],
        ] as const).map(([id, label, icon]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cx("-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium", tab === id ? "border-teal-600 text-teal-700 dark:text-teal-300" : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200")}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>
      {tab === "audit" ? <AuditTable /> : <SessionsTable />}
    </>
  );
}

function AuditTable() {
  const [filters, setFilters] = useState({ action: "", user: "", result: "", severity: "", q: "" });
  const [draft, setDraft] = useState(filters);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const { data, error, loading, reload } = useLoader(
    () => api.get<{ total: number; actions: string[]; items: AuditEntry[] }>("/api/audit", { ...filters, limit: PAGE, offset }),
    [filters, offset],
  );

  return (
    <>
      <Card
        padded={false}
        title="Audit log"
        actions={
          <a href={buildUrl("/api/audit/export", filters)} download>
            <Button size="sm" icon={<Download className="h-3.5 w-3.5" />}>
              Export CSV
            </Button>
          </a>
        }
      >
        <form
          className="flex flex-wrap gap-3 border-b border-slate-200 p-3 dark:border-slate-800"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setFilters(draft);
          }}
        >
          <Select className="w-56" aria-label="Filter by action" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
            <option value="">All actions</option>
            {data?.actions.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
          <Select className="w-36" aria-label="Filter by severity" value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
            <option value="">All severities</option>
            <option>INFO</option>
            <option>WARNING</option>
            <option>HIGH</option>
            <option>CRITICAL</option>
          </Select>
          <Select className="w-36" aria-label="Filter by result" value={draft.result} onChange={(e) => setDraft({ ...draft, result: e.target.value })}>
            <option value="">All results</option>
            <option>SUCCESS</option>
            <option>FAILED</option>
            <option>DENIED</option>
            <option>BLOCKED</option>
            <option>INFO</option>
          </Select>
          <Input className="w-40" placeholder="User" value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} />
          <Input className="w-64" placeholder="Search switch, port, MAC, message" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
          <Button type="submit">Apply</Button>
        </form>
        {error ? (
          <div className="p-4">
            <ErrorBanner error={error} onRetry={() => reload()} />
          </div>
        ) : loading && !data ? (
          <Loading />
        ) : !data?.items.length ? (
          <EmptyState icon={<FileClock className="h-8 w-8" />} title="No audit entries" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>Severity</Th>
                  <Th>User</Th>
                  <Th>Role</Th>
                  <Th>Action</Th>
                  <Th>Result</Th>
                  <Th>Switch</Th>
                  <Th>Port</Th>
                  <Th>MAC</Th>
                  <Th>Message</Th>
                  <Th>IP</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => setSelected(a)}>
                    <Td className="whitespace-nowrap">{fmtDateTime(a.ts)}</Td>
                    <Td>
                      <SeverityBadge severity={a.severity} />
                    </Td>
                    <Td>{a.username}</Td>
                    <Td className="text-xs text-slate-500">{a.role || ""}</Td>
                    <Td mono>
                      {a.action}
                      {a.operation && a.operation !== a.action && <div className="text-[11px] text-slate-500">{a.operation}</div>}
                    </Td>
                    <Td>
                      <Badge tone={resultTone(a.result)}>{a.result}</Badge>
                    </Td>
                    <Td className="whitespace-nowrap">{a.switch_name}</Td>
                    <Td mono>{a.port}</Td>
                    <Td mono>{a.mac ? formatMac(a.mac) : ""}</Td>
                    <Td className="max-w-sm truncate">{a.message || a.target_label}</Td>
                    <Td mono className="text-slate-500">
                      {a.ip}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={data.total} offset={offset} page={PAGE} onChange={setOffset} />
          </>
        )}
      </Card>
      {selected && (
        <Modal open onClose={() => setSelected(null)} width="max-w-2xl" title={`${selected.action} · ${selected.result}`}>
          <div className="space-y-2 text-sm">
            <div>
              <strong>Time:</strong> {fmtDateTime(selected.ts)}
            </div>
            <div className="flex items-center gap-2">
              <strong>Severity:</strong> <SeverityBadge severity={selected.severity} />
            </div>
            <div>
              <strong>User:</strong> {selected.username} {selected.ip && `(${selected.ip})`}
            </div>
            {selected.target_type && (
              <div>
                <strong>Target:</strong> {selected.target_type} {selected.target_label || selected.target_id}
              </div>
            )}
            {selected.message && (
              <div>
                <strong>Message:</strong> {selected.message}
              </div>
            )}
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-3">
              {(
                [
                  ["Role", selected.role],
                  ["Operation", selected.operation],
                  ["Switch", selected.switch_name],
                  ["Port", selected.port],
                  ["MAC", selected.mac ? formatMac(selected.mac) : ""],
                  ["VLAN", selected.vlan ?? ""],
                  ["Profile", selected.profile],
                  ["Risk", selected.risk_level],
                  ["Approval", selected.approval],
                ] as const
              )
                .filter(([, v]) => v !== undefined && v !== null && v !== "")
                .map(([k, v]) => (
                  <div key={k}>
                    <dt className="text-[11px] uppercase tracking-wide text-slate-500">{k}</dt>
                    <dd className="break-words">{String(v)}</dd>
                  </div>
                ))}
            </dl>
            {selected.command_fingerprint && (
              <div>
                <strong>Command fingerprint:</strong> <span className="mono break-all text-xs">{selected.command_fingerprint}</span>
              </div>
            )}
            {selected.error && (
              <div className="text-red-700 dark:text-red-400">
                <strong>Error:</strong> {selected.error}
              </div>
            )}
            {(selected.before_state || selected.after_state) && (
              <div className="grid gap-2 sm:grid-cols-2">
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Before</div>
                  <pre className="mono max-h-60 overflow-auto rounded-lg bg-slate-100 p-2 text-[11px] dark:bg-slate-950">{JSON.stringify(selected.before_state, null, 2)}</pre>
                </div>
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">After</div>
                  <pre className="mono max-h-60 overflow-auto rounded-lg bg-slate-100 p-2 text-[11px] dark:bg-slate-950">{JSON.stringify(selected.after_state, null, 2)}</pre>
                </div>
              </div>
            )}
            <pre className="mono mt-3 max-h-96 overflow-auto rounded-lg bg-slate-100 p-3 text-xs dark:bg-slate-950">{JSON.stringify(selected.details, null, 2)}</pre>
            <p className="text-xs text-slate-500">Audit entries are append-only: the database rejects any update or deletion.</p>
          </div>
        </Modal>
      )}
    </>
  );
}

function SessionsTable() {
  const [result, setResult] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<SshSessionItem | null>(null);
  const { data, error, loading, reload } = useLoader(
    () => api.get<{ total: number; items: SshSessionItem[] }>("/api/ssh-sessions", { result, limit: PAGE, offset }),
    [result, offset],
  );
  return (
    <>
      <Card padded={false} title="SSH sessions (Command Safety Firewall)">
        <div className="flex gap-3 border-b border-slate-200 p-3 dark:border-slate-800">
          <Select
            className="w-52"
            aria-label="Filter SSH sessions by result"
            value={result}
            onChange={(e) => {
              setOffset(0);
              setResult(e.target.value);
            }}
          >
            <option value="">All results</option>
            <option value="success">Success</option>
            <option value="failed">Failed</option>
            <option value="blocked">Blocked</option>
            <option value="connect_failed">Connect failed</option>
          </Select>
        </div>
        {error ? (
          <div className="p-4">
            <ErrorBanner error={error} onRetry={() => reload()} />
          </div>
        ) : loading && !data ? (
          <Loading />
        ) : !data?.items.length ? (
          <EmptyState icon={<TerminalSquare className="h-8 w-8" />} title="No SSH sessions recorded" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Started</Th>
                  <Th>Switch</Th>
                  <Th>User</Th>
                  <Th>Purpose</Th>
                  <Th>Operations</Th>
                  <Th>Attempted</Th>
                  <Th>Executed</Th>
                  <Th>Blocked</Th>
                  <Th>Result</Th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => setSelected(s)}>
                    <Td className="whitespace-nowrap">{fmtDateTime(s.started_at)}</Td>
                    <Td className="whitespace-nowrap font-medium">{s.switch_name}</Td>
                    <Td>{s.username}</Td>
                    <Td mono className="text-xs">{s.purpose}</Td>
                    <Td mono className="text-xs">{s.operations.join(", ")}</Td>
                    <Td className="tnum">{s.commands_attempted}</Td>
                    <Td className="tnum">{s.commands_executed}</Td>
                    <Td className={cx("tnum", s.commands_blocked > 0 && "font-semibold text-red-600")}>{s.commands_blocked}</Td>
                    <Td>
                      <Badge tone={s.result === "success" ? "green" : s.result === "blocked" ? "red" : "amber"}>{s.result}</Badge>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={data.total} offset={offset} page={PAGE} onChange={setOffset} />
          </>
        )}
      </Card>
      {selected && (
        <Modal open onClose={() => setSelected(null)} width="max-w-3xl" title={`SSH session — ${selected.switch_name}`}>
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div><strong>User:</strong> {selected.username}</div>
              <div><strong>Purpose:</strong> {selected.purpose}</div>
              <div><strong>Profile:</strong> {selected.profile_key || "—"}</div>
              <div><strong>Result:</strong> {selected.result}</div>
            </div>
            {selected.error && <div className="text-red-700 dark:text-red-400">{selected.error}</div>}
            <Table>
              <thead>
                <tr>
                  <Th>Operation</Th>
                  <Th>Command</Th>
                  <Th>Risk</Th>
                  <Th>Status</Th>
                  <Th>Fingerprint</Th>
                  <Th>ms</Th>
                </tr>
              </thead>
              <tbody>
                {selected.commands.map((c, i) => (
                  <tr key={i}>
                    <Td mono className="text-xs">{c.operation}</Td>
                    <Td mono className="text-xs">{c.command_key}</Td>
                    <Td className="text-xs">{c.risk}</Td>
                    <Td>
                      <Badge tone={c.status === "executed" ? "green" : c.status === "blocked" ? "red" : "amber"}>{c.status}</Badge>
                      {c.reason && <div className="mt-1 max-w-xs text-xs text-slate-500">{c.reason}</div>}
                    </Td>
                    <Td mono className="text-xs" >{c.fingerprint ? c.fingerprint.slice(0, 16) : "—"}</Td>
                    <Td className="tnum text-xs">{c.duration_ms}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <p className="text-xs text-slate-500">Commands are identified by fingerprint (SHA-256 of profile and command text); the command text itself is not stored in the session log.</p>
          </div>
        </Modal>
      )}
    </>
  );
}
