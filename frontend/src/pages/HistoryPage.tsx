import { Download, Eye, History, RotateCw, Shuffle } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, buildUrl } from "../api/client";
import type { HistoryItem, MacSearch } from "../api/types";
import { Badge, Button, Card, EmptyState, ErrorBanner, Input, Loading, PageHeader, Table, Td, Th } from "../components/ui";
import { fmtDateTime, fmtDuration } from "../lib/format";
import { useLoader } from "../lib/hooks";

const PAGE = 50;

function resultBadge(result: string) {
  if (result === "FOUND") return <Badge tone="green">Found</Badge>;
  if (result === "NOT_FOUND") return <Badge>Not found</Badge>;
  if (result === "NOT_FOUND_WITH_ERRORS") return <Badge tone="amber">Not found · errors</Badge>;
  return <Badge tone="blue">{result.toLowerCase()}</Badge>;
}

export default function HistoryPage() {
  const navigate = useNavigate();
  const [mac, setMac] = useState("");
  const [user, setUser] = useState("");
  const [applied, setApplied] = useState({ mac: "", user: "" });
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useLoader(
    () => api.get<{ total: number; items: HistoryItem[] }>("/api/search-history", { ...applied, limit: PAGE, offset }),
    [applied, offset],
  );
  const [rerunError, setRerunError] = useState<unknown>(null);

  async function searchAgain(item: HistoryItem) {
    setRerunError(null);
    try {
      const s = await api.post<MacSearch>("/api/mac/search", { mac: item.mac });
      navigate(`/mac-search/${s.id}`);
    } catch (e) {
      setRerunError(e);
    }
  }

  return (
    <>
      <PageHeader
        title="Search History"
        subtitle="Every MAC search with its outcome"
        actions={
          <a href={buildUrl("/api/search-history/export", applied)} download>
            <Button icon={<Download className="h-4 w-4" />}>Export CSV</Button>
          </a>
        }
      />
      <Card padded={false}>
        <form
          className="flex flex-wrap items-end gap-3 border-b border-slate-200 p-3 dark:border-slate-800"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setApplied({ mac: mac.trim(), user: user.trim() });
          }}
        >
          <Input className="mono w-64" placeholder="MAC (any format)" value={mac} onChange={(e) => setMac(e.target.value)} />
          <Input className="w-44" placeholder="User" value={user} onChange={(e) => setUser(e.target.value)} />
          <Button type="submit">Filter</Button>
          {(applied.mac || applied.user) && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setMac("");
                setUser("");
                setApplied({ mac: "", user: "" });
              }}
            >
              Clear
            </Button>
          )}
        </form>
        <div className="p-3 empty:hidden">
          <ErrorBanner error={error || rerunError} onRetry={error ? () => reload() : undefined} />
        </div>
        {loading && !data ? (
          <Loading />
        ) : !data?.items.length ? (
          <EmptyState icon={<History className="h-8 w-8" />} title="No searches found" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>User</Th>
                  <Th>MAC</Th>
                  <Th>Switch</Th>
                  <Th>Port</Th>
                  <Th>VLAN</Th>
                  <Th>Result</Th>
                  <Th>Checked</Th>
                  <Th>Duration</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr key={i.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <Td className="whitespace-nowrap">{fmtDateTime(i.time)}</Td>
                    <Td>{i.user}</Td>
                    <Td mono>{i.mac}</Td>
                    <Td>
                      {i.switch || "—"}
                      {i.locations > 1 && <span className="ml-1 text-xs text-slate-500">(+{i.locations - 1})</span>}
                    </Td>
                    <Td mono>{i.port || "—"}</Td>
                    <Td mono>{i.vlan ?? "—"}</Td>
                    <Td>
                      <div className="flex items-center gap-1">
                        {resultBadge(i.result)}
                        {i.mac_move && (
                          <Badge tone="red">
                            <Shuffle className="h-3 w-3" /> moved
                          </Badge>
                        )}
                      </div>
                    </Td>
                    <Td className="tnum text-slate-500">
                      {i.checked}/{i.total}
                      {i.failed > 0 && <span className="text-amber-600"> · {i.failed} failed</span>}
                    </Td>
                    <Td className="tnum whitespace-nowrap text-slate-500">{fmtDuration(i.duration_ms)}</Td>
                    <Td className="whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" icon={<Eye className="h-3.5 w-3.5" />} onClick={() => navigate(`/mac-search/${i.id}`)}>
                        Details
                      </Button>
                      <Button size="sm" variant="ghost" icon={<RotateCw className="h-3.5 w-3.5" />} onClick={() => searchAgain(i)}>
                        Search again
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Pager total={data.total} offset={offset} page={PAGE} onChange={setOffset} />
          </>
        )}
      </Card>
    </>
  );
}

export function Pager({ total, offset, page, onChange }: { total: number; offset: number; page: number; onChange: (o: number) => void }) {
  if (total <= page) return <div className="px-4 py-3 text-xs text-slate-500">{total} entries</div>;
  return (
    <div className="flex items-center justify-between px-4 py-3 text-xs text-slate-500">
      <span>
        {offset + 1}–{Math.min(offset + page, total)} of {total}
      </span>
      <div className="flex gap-2">
        <Button size="sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - page))}>
          Previous
        </Button>
        <Button size="sm" disabled={offset + page >= total} onClick={() => onChange(offset + page)}>
          Next
        </Button>
      </div>
    </div>
  );
}
