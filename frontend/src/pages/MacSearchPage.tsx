import { AlertTriangle, ArrowRight, ChevronRight, LayoutGrid, List, MapPin, RefreshCw, Route, SearchX, Shuffle } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { MacSearch, MacSearchResult, NetworkPath } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { MacSearchBox } from "../components/MacSearchBox";
import { RestartDialog } from "../components/RestartDialog";
import { ResultCard } from "../components/ResultCard";
import { ResultDetails } from "../components/ResultDetails";
import { Badge, Button, Card, ClassBadge, EmptyState, ErrorBanner, Loading, Notice, PageHeader, ResultStatusBadge, Table, Td, Th, cx } from "../components/ui";
import { fmtDateTime, fmtDuration } from "../lib/format";

const FINAL = new Set(["completed", "failed", "interrupted"]);
const ORDER: Record<string, number> = { ACCESS: 0, LIKELY_ACCESS: 1, UNKNOWN: 2, LIKELY_TRUNK: 3, TRUNK: 4, "": 5 };

export default function MacSearchPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  return (
    <>
      <PageHeader title="MAC Search" subtitle="Locate a MAC address across all enabled OmniSwitches (read-only)" />
      <Card className="mb-6">
        <MacSearchBox key={id || "new"} onStarted={(sid) => navigate(`/mac-search/${sid}`)} />
      </Card>
      {id ? (
        <SearchJob id={id} />
      ) : (
        <Card>
          <EmptyState icon={<MapPin className="h-8 w-8" />} title="Enter a MAC address to begin">
            Every enabled switch is queried with a MAC-filtered, read-only command. When the MAC is found, only that port is inspected (VLANs, status, LLDP, MAC count) and classified as access or trunk.
          </EmptyState>
        </Card>
      )}
    </>
  );
}

function SearchJob({ id }: { id: string }) {
  const navigate = useNavigate();
  const [search, setSearch] = useState<MacSearch | null>(null);
  const [results, setResults] = useState<MacSearchResult[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [details, setDetails] = useState<MacSearchResult | null>(null);
  const [restart, setRestart] = useState<MacSearchResult | null>(null);
  const [view, setView] = useState<"table" | "cards">("table");
  const { can } = useAuth();
  const refreshTimer = useRef<number | null>(null);

  const loadAll = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([api.get<MacSearch>(`/api/mac/search/${id}`), api.get<MacSearchResult[]>(`/api/mac/search/${id}/results`)]);
      setSearch(s);
      setResults(r);
    } catch (e) {
      setError(e);
    }
  }, [id]);

  const scheduleResults = useCallback(() => {
    if (refreshTimer.current) return;
    refreshTimer.current = window.setTimeout(async () => {
      refreshTimer.current = null;
      try {
        setResults(await api.get<MacSearchResult[]>(`/api/mac/search/${id}/results`));
      } catch {
        /* next event will retry */
      }
    }, 250);
  }, [id]);

  useEffect(() => {
    setSearch(null);
    setResults([]);
    setError(null);
    loadAll();
    const es = new EventSource(`/api/mac/search/${id}/events`);
    es.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "snapshot") setSearch(msg.search);
      else if (msg.type === "progress")
        setSearch((prev) => (prev ? { ...prev, status: msg.status, checked: msg.checked, total_switches: msg.total, found_count: msg.found, failed_count: msg.failed, timeout_count: msg.timeout } : prev));
      else if (msg.type === "switch") scheduleResults();
      else if (msg.type === "done") {
        es.close();
        loadAll();
      }
    };
    es.onerror = () => {
      // Fall back to polling if the stream is interrupted (proxy timeouts etc.).
      es.close();
      const poll = window.setInterval(async () => {
        const s = await api.get<MacSearch>(`/api/mac/search/${id}`).catch(() => null);
        if (s) setSearch(s);
        if (!s || FINAL.has(s.status)) {
          window.clearInterval(poll);
          loadAll();
        }
      }, 1500);
    };
    return () => {
      es.close();
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
    };
  }, [id, loadAll, scheduleResults]);

  const found = useMemo(() => results.filter((r) => r.status === "found").sort((a, b) => (ORDER[a.classification] ?? 9) - (ORDER[b.classification] ?? 9)), [results]);
  const perSwitch = useMemo(() => {
    const map = new Map<string, MacSearchResult>();
    for (const r of results) if (!map.has(r.switch_name) || r.status === "found") map.set(r.switch_name, r);
    return [...map.values()].sort((a, b) => a.switch_name.localeCompare(b.switch_name));
  }, [results]);
  const failed = perSwitch.filter((r) => !["found", "not_found"].includes(r.status));

  if (error && !search) return <ErrorBanner error={error} onRetry={loadAll} />;
  if (!search) return <Loading label="Loading search…" />;

  const done = FINAL.has(search.status);
  const pct = search.total_switches ? Math.round((search.checked / search.total_switches) * 100) : 0;
  const summary = search.summary || {};
  const edge = summary.likely_edge;

  async function retryFailed() {
    const ids = failed.map((f) => f.switch_id).filter((x): x is number => x !== null);
    const s = await api.post<MacSearch>("/api/mac/search", { mac: search!.mac, switch_ids: ids });
    navigate(`/mac-search/${s.id}`);
  }

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">MAC address</div>
            <div className="mono text-3xl font-semibold tracking-tight">{search.mac_display}</div>
            <div className="mt-1 text-xs text-slate-500">
              Started {fmtDateTime(search.created_at)} by {search.requested_by}
              {search.duration_ms !== null && ` · ${fmtDuration(search.duration_ms)}`}
              <Badge className="ml-2" tone={search.mode === "DEEP" ? "violet" : search.mode === "FAST" ? "blue" : "slate"}>
                {search.mode || "STANDARD"} mode
              </Badge>
            </div>
          </div>
          <div className="text-right">
            {!done ? (
              <Badge tone="blue" className="px-3 py-1.5 text-sm">
                Searching {search.total_switches} switches…
              </Badge>
            ) : search.status !== "completed" ? (
              <Badge tone="red" className="px-3 py-1.5 text-sm uppercase">
                Search {search.status}
              </Badge>
            ) : search.found_count > 0 ? (
              <Badge tone="green" className="px-3 py-1.5 text-sm">
                FOUND on {search.found_count} switch{search.found_count > 1 ? "es" : ""}
              </Badge>
            ) : (
              <Badge tone="slate" className="px-3 py-1.5 text-sm">
                NOT FOUND
              </Badge>
            )}
          </div>
        </div>

        <div className="mt-5">
          <div className="mb-1.5 flex justify-between text-xs text-slate-500">
            <span className="tnum">
              {search.checked} / {search.total_switches} switches checked
            </span>
            <span className="tnum font-semibold">{pct}%</span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
            <div className={cx("h-full rounded-full bg-teal-600 transition-all duration-500", !done && "progress-active")} style={{ width: `${Math.max(pct, done ? 100 : 2)}%` }} />
          </div>
          <div className="tnum mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
            <span>
              Found: <strong className="text-emerald-600">{search.found_count}</strong>
            </span>
            <span>
              Failed: <strong className={search.failed_count ? "text-red-600" : ""}>{search.failed_count}</strong>
            </span>
            <span>
              Timeout: <strong className={search.timeout_count ? "text-amber-600" : ""}>{search.timeout_count}</strong>
            </span>
          </div>
        </div>
      </Card>

      {summary.mac_move && (
        <Notice tone="red" icon={<Shuffle className="mt-0.5 h-5 w-5" />} title="MAC MOVE DETECTED">
          <div className="mt-1 flex flex-wrap items-center gap-3 text-sm">
            <span>
              Previous: <strong>{summary.mac_move.previous.switch_name}</strong> / <span className="mono">{summary.mac_move.previous.port}</span>{" "}
              <span className="text-xs opacity-75">({fmtDateTime(summary.mac_move.previous.seen_at)})</span>
            </span>
            <ArrowRight className="h-4 w-4" />
            <span>
              Current: <strong>{summary.mac_move.current.switch_name}</strong> / <span className="mono">{summary.mac_move.current.port}</span>{" "}
              <span className="text-xs opacity-75">({fmtDateTime(summary.mac_move.current.seen_at)})</span>
            </span>
          </div>
          <div className="mt-1 text-xs opacity-80">No corrective action is taken automatically.</div>
        </Notice>
      )}

      {summary.multiple_locations && (
        <Notice tone="amber" icon={<AlertTriangle className="mt-0.5 h-5 w-5" />} title={`Multiple MAC locations detected (${summary.locations})`}>
          <p>The result is not reduced to a single location automatically. Possible reasons:</p>
          <ul className="mt-1 list-disc pl-5 text-sm">
            {summary.multiple_location_reasons?.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          {edge && (
            <p className="mt-2 text-sm">
              Hint: only one location is an access-type port — <strong>{edge.switch_name}</strong> <span className="mono">{edge.port}</span> (VLAN {edge.vlan_id ?? "?"}). The others look like uplinks.
            </p>
          )}
          {summary.edge_warning && <p className="mt-2 text-sm font-medium">{summary.edge_warning}</p>}
        </Notice>
      )}

      {done && summary.path && found.length > 0 && <PathPanel path={summary.path} />}

      {found.length > 0 && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">MAC search results</h2>
            <div className="flex gap-1">
              <Button size="sm" variant={view === "table" ? "secondary" : "ghost"} icon={<List className="h-3.5 w-3.5" />} onClick={() => setView("table")}>
                Table
              </Button>
              <Button size="sm" variant={view === "cards" ? "secondary" : "ghost"} icon={<LayoutGrid className="h-3.5 w-3.5" />} onClick={() => setView("cards")}>
                Cards
              </Button>
            </div>
          </div>
          {view === "cards" ? (
            <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
              {found.map((r) => (
                <ResultCard key={r.id} r={r} highlight={!!edge && summary.multiple_locations && edge.switch_name === r.switch_name && edge.port === r.port} onDetails={() => setDetails(r)} onRestart={() => setRestart(r)} />
              ))}
            </div>
          ) : (
            <Card padded={false}>
              <Table>
                <thead>
                  <tr>
                    <Th>Switch</Th>
                    <Th>Port</Th>
                    <Th>VLAN</Th>
                    <Th>Status</Th>
                    <Th>MACs</Th>
                    <Th>LLDP</Th>
                    <Th>Classification</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {found.map((r) => (
                    <tr key={r.id} className={cx(!!edge && edge.switch_name === r.switch_name && edge.port === r.port && "bg-emerald-50/60 dark:bg-emerald-500/5")}>
                      <Td>
                        <div className="font-medium">{r.switch_name}</div>
                        <div className="mono text-xs text-slate-500">{r.switch_host} · {r.model} · {r.aos_version}</div>
                      </Td>
                      <Td mono>{r.port || r.interface_raw}</Td>
                      <Td mono>{r.vlan_id ?? "—"}</Td>
                      <Td>{r.port_details?.oper_status ? <Badge tone={r.port_details.oper_status === "up" ? "green" : "red"}>{r.port_details.oper_status.toUpperCase()}</Badge> : "—"}</Td>
                      <Td className="tnum">{r.mac_count_on_port ?? "—"}</Td>
                      <Td className="text-xs">{r.lldp.length ? r.lldp.map((n) => n.system_name || n.chassis_id).join(", ") : "none"}</Td>
                      <Td>
                        <ClassBadge value={r.classification} confidence={r.classification_confidence} />
                      </Td>
                      <Td className="whitespace-nowrap text-right">
                        <Button size="sm" variant="ghost" onClick={() => setDetails(r)}>
                          Evidence
                        </Button>
                        {r.switch_id && r.port && can("port_inspect") && (
                          <Link className="inline-flex h-8 items-center gap-1 rounded-lg px-2.5 text-xs font-medium text-teal-700 hover:bg-slate-100 dark:text-teal-400 dark:hover:bg-slate-800" to={`/port?switch=${r.switch_id}&port=${encodeURIComponent(r.port)}&mac=${search.mac}`}>
                            Port <ChevronRight className="h-3.5 w-3.5" />
                          </Link>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          )}
        </div>
      )}

      {done && search.status === "completed" && found.length === 0 && (
        <Card>
          <EmptyState icon={<SearchX className="h-8 w-8" />} title="MAC not found on any reachable switch">
            {failed.length > 0 ? `${failed.length} switch(es) could not be checked — see below.` : "The MAC may have aged out of the MAC tables, or the device is on a switch that is not in the inventory."}
          </EmptyState>
        </Card>
      )}

      <Card
        title={`Switches checked (${perSwitch.length}/${search.total_switches})`}
        padded={false}
        actions={
          done && failed.length > 0 ? (
            <Button size="sm" icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={retryFailed}>
              Retry {failed.length} failed
            </Button>
          ) : undefined
        }
      >
        <Table>
          <thead>
            <tr>
              <Th>Switch</Th>
              <Th>Result</Th>
              <Th>Detail</Th>
              <Th className="text-right">Time</Th>
            </tr>
          </thead>
          <tbody>
            {perSwitch.map((r) => (
              <tr key={r.switch_name}>
                <Td>
                  <div className="font-medium">{r.switch_name}</div>
                  <div className="mono text-xs text-slate-500">{r.switch_host}</div>
                </Td>
                <Td>
                  <ResultStatusBadge status={r.status} />
                </Td>
                <Td className="max-w-xl text-sm">
                  {r.status === "found" ? (
                    <span className="mono">
                      {found.filter((f) => f.switch_name === r.switch_name).map((f) => f.port || f.interface_raw).join(", ")}
                    </span>
                  ) : r.error_message ? (
                    <span className="text-red-700 dark:text-red-400">{r.error_message}</span>
                  ) : (
                    <span className="text-slate-500">MAC not in table</span>
                  )}
                </Td>
                <Td className="tnum text-right text-slate-500">{fmtDuration(r.duration_ms)}</Td>
              </tr>
            ))}
            {!done &&
              Array.from({ length: Math.max(0, search.total_switches - perSwitch.length) }).map((_, i) => (
                <tr key={`p${i}`}>
                  <Td className="text-slate-400">…</Td>
                  <Td>
                    <ResultStatusBadge status="pending" />
                  </Td>
                  <Td />
                  <Td />
                </tr>
              ))}
          </tbody>
        </Table>
      </Card>

      {details && (
        <ResultDetails
          r={details}
          mac={search.mac}
          onClose={() => setDetails(null)}
          onRestart={() => {
            setRestart(details);
            setDetails(null);
          }}
        />
      )}
      {restart && <RestartDialog target={{ searchResultId: restart.id, switchName: restart.switch_name }} onClose={() => setRestart(null)} />}
    </div>
  );
}

const PATH_TONE: Record<string, "green" | "amber" | "red" | "slate"> = { RESOLVED: "green", PARTIAL: "amber", AMBIGUOUS: "red", NO_EDGE: "slate", NOT_FOUND: "slate" };

/** §17: path derived from the search's own evidence (edge port + LLDP neighbors + topology roles). */
function PathPanel({ path }: { path: NetworkPath }) {
  return (
    <Card title={<span className="flex items-center gap-2"><Route className="h-4 w-4" /> Network path</span>} actions={<Badge tone={PATH_TONE[path.status] || "slate"}>{path.status}</Badge>}>
      {path.hops.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-lg bg-slate-100 px-3 py-2 text-sm font-semibold dark:bg-slate-800">Device</span>
          {path.hops.map((h) => (
            <span key={`${h.switch_name}-${h.interface}`} className="flex items-center gap-2">
              <ArrowRight className="h-4 w-4 text-slate-400" />
              <span className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm dark:border-slate-700">
                <span className="font-semibold">{h.switch_name}</span> <span className="mono">{h.interface}</span>
                <span className="block text-[11px] uppercase tracking-wide text-slate-500">
                  {h.role} · {h.classification.replace("_", " ")}
                </span>
              </span>
            </span>
          ))}
        </div>
      ) : (
        <p className="text-sm text-slate-500">No path could be anchored to a single access port.</p>
      )}
      {path.unlinked.length > 0 && (
        <p className="mt-3 text-xs text-slate-500">
          Also seen on (not linked by LLDP evidence): {path.unlinked.map((h) => `${h.switch_name} ${h.interface}`).join(", ")}
        </p>
      )}
      {path.notes.map((n) => (
        <p key={n} className="mt-1 text-xs text-slate-500">{n}</p>
      ))}
    </Card>
  );
}
