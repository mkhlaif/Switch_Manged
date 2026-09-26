import { ArrowDownRight, ArrowUpRight, Minus, Power } from "lucide-react";
import type { MacSearchResult, Reason } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtDuration, fmtSpeed, formatMac } from "../lib/format";
import { restartEligibility } from "./ResultCard";
import { Badge, Button, ClassBadge, CodeBlock, Drawer, KV, Notice, Table, Td, Th } from "./ui";

export function ReasonList({ reasons }: { reasons: Reason[] }) {
  return (
    <ul className="space-y-1.5">
      {reasons.map((r, i) => (
        <li key={i} className="flex items-start gap-2 text-sm">
          {r.indicates === "trunk" ? (
            <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-orange-500" aria-label="points to trunk" />
          ) : r.indicates === "access" ? (
            <ArrowDownRight className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" aria-label="points to access" />
          ) : (
            <Minus className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-label="informational" />
          )}
          <span>{r.text}</span>
        </li>
      ))}
    </ul>
  );
}

export function ResultDetails({ r, mac, onClose, onRestart }: { r: MacSearchResult; mac: string; onClose: () => void; onRestart: () => void }) {
  const { user } = useAuth();
  const d = r.port_details || {};
  const elig = restartEligibility(r, user?.role || "readonly");
  return (
    <Drawer
      open
      onClose={onClose}
      title={
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-lg font-semibold">{r.switch_name}</span>
            <span className="mono text-lg">{r.port || r.interface_raw}</span>
            <ClassBadge value={r.classification} confidence={r.classification_confidence} />
          </div>
          <div className="mono text-xs text-slate-500">MAC {formatMac(mac)}</div>
        </div>
      }
      footer={
        elig.allowed ? (
          <Button variant="danger" icon={<Power className="h-4 w-4" />} onClick={onRestart}>
            Restart port…
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-6">
        {r.warnings.length > 0 && (
          <Notice tone="amber" title="Partial information">
            <ul className="list-disc pl-4">
              {r.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </Notice>
        )}

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Switch</h4>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KV label="Name">{r.switch_name}</KV>
            <KV label="IP / host" mono>{r.switch_host}</KV>
            <KV label="Model">{r.model || "—"}</KV>
            <KV label="AOS" mono>{r.aos_version || "—"}</KV>
            <KV label="Location">{r.location || "—"}</KV>
            <KV label="Command profile">{r.profile_key}</KV>
            <KV label="Lookup time">{fmtDuration(r.duration_ms)}</KV>
          </dl>
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">MAC learning</h4>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KV label="VLAN" mono>{r.vlan_id ?? "—"}</KV>
            <KV label="Type">{r.mac_type || "—"}</KV>
            <KV label="Operation">{r.operation || "—"}</KV>
            <KV label="Interface" mono>{r.interface_raw}</KV>
            <KV label="MACs on port" mono>{r.mac_count_on_port ?? "—"}</KV>
          </dl>
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Port</h4>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KV label="Admin status">{d.admin_status || "—"}</KV>
            <KV label="Operational">{d.oper_status || d.link_status || "—"}</KV>
            <KV label="Speed">{fmtSpeed(d.speed_mbps)}</KV>
            <KV label="Duplex">{d.duplex || "—"}</KV>
            <KV label="Description">{d.alias || "—"}</KV>
            <KV label="Media">{[d.interface_type, d.transceiver].filter(Boolean).join(" · ") || "—"}</KV>
            <KV label="Last link change">{d.last_link_change || "—"}</KV>
            <KV label="Status changes" mono>{d.status_changes ?? "—"}</KV>
            <KV label="Rx errors" mono>{d.rx_errors ?? "—"}</KV>
            <KV label="Tx errors" mono>{d.tx_errors ?? "—"}</KV>
            <KV label="Rx unicast" mono>{d.rx?.unicast_frames ?? "—"}</KV>
            <KV label="Tx unicast" mono>{d.tx?.unicast_frames ?? "—"}</KV>
          </dl>
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
            Port classification · {r.classification.replace("_", " ")}{" "}
            {r.classification_score !== null && <span className="normal-case">(confidence {Math.round((r.classification_score || 0) * 100)}%)</span>}
          </h4>
          <ReasonList reasons={r.classification_reasons} />
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">VLAN membership of {r.port || r.interface_raw}</h4>
          {r.vlans.length ? (
            <Table>
              <thead>
                <tr>
                  <Th>VLAN</Th>
                  <Th>Mode</Th>
                  <Th>Reported type</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody>
                {r.vlans.map((v) => (
                  <tr key={v.vlan_id}>
                    <Td mono>{v.vlan_id}</Td>
                    <Td>{v.tagged === true ? <Badge tone="orange">tagged</Badge> : v.tagged === false ? <Badge tone="green">untagged</Badge> : <Badge>{v.mode}</Badge>}</Td>
                    <Td mono>{v.mode_raw}</Td>
                    <Td>{v.status}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-sm text-slate-500">No VLAN information.</p>
          )}
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">LLDP neighbors</h4>
          {r.lldp.length ? (
            <Table>
              <thead>
                <tr>
                  <Th>Local port</Th>
                  <Th>Remote system</Th>
                  <Th>Remote port</Th>
                  <Th>Chassis / MAC</Th>
                  <Th>Mgmt IP</Th>
                  <Th>Capabilities</Th>
                </tr>
              </thead>
              <tbody>
                {r.lldp.map((n, i) => (
                  <tr key={i}>
                    <Td mono>{n.local_port}</Td>
                    <Td>
                      <div className="font-medium">{n.system_name || "—"}</div>
                      {n.system_description && <div className="text-xs text-slate-500">{n.system_description}</div>}
                    </Td>
                    <Td mono>{n.port_description || n.port_id || "—"}</Td>
                    <Td mono>{n.chassis_id || "—"}</Td>
                    <Td mono>{n.management_ip || "—"}</Td>
                    <Td>{n.capabilities.join(", ") || "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-sm text-slate-500">No LLDP neighbor detected on this port.</p>
          )}
        </section>

        <section>
          <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">Read-only commands executed ({r.profile_key})</h4>
          <CodeBlock lines={r.commands_executed} />
        </section>
      </div>
    </Drawer>
  );
}
