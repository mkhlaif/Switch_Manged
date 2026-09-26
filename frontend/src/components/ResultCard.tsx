import { Info, Power, Radio } from "lucide-react";
import type { MacSearchResult, Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtSpeed } from "../lib/format";
import { Badge, Button, ClassBadge, KV, cx } from "./ui";

export function restartEligibility(r: MacSearchResult, role: Role): { allowed: boolean; reason: string } {
  // UI hint only; the backend re-evaluates the full restart policy on every request.
  if (role === "readonly" || role === "mac_operator") return { allowed: false, reason: "Your role cannot restart ports from this view." };
  if (r.is_linkagg || !r.port) return { allowed: false, reason: "Learned on a link aggregate / non-physical interface." };
  if (!r.classification || r.classification === "UNKNOWN") {
    return { allowed: false, reason: "The port classification is uncertain (UNKNOWN): a restart is never offered. Run a STANDARD search for full evidence." };
  }
  if (r.classification === "TRUNK" || r.classification === "LIKELY_TRUNK") {
    if (role !== "admin") return { allowed: false, reason: "Trunk / uplink ports cannot be restarted." };
    return { allowed: true, reason: "Administrator override: only possible in EMERGENCY mode with two typed confirmations." };
  }
  if (role === "operator" && !["ACCESS", "LIKELY_ACCESS"].includes(r.classification)) {
    return { allowed: false, reason: `Operators cannot restart ${r.classification.replace("_", " ")} ports.` };
  }
  return { allowed: true, reason: "" };
}

export function ResultCard({ r, highlight, onDetails, onRestart }: { r: MacSearchResult; highlight?: boolean; onDetails: () => void; onRestart: () => void }) {
  const { user } = useAuth();
  const eligibility = restartEligibility(r, user?.role || "readonly");
  const trunkish = r.classification === "TRUNK" || r.classification === "LIKELY_TRUNK";
  const d = r.port_details || {};
  const neighbor = r.lldp?.[0];
  const oper = d.oper_status || d.link_status;

  return (
    <article
      className={cx(
        "flex flex-col rounded-xl border bg-white shadow-sm dark:bg-slate-900",
        highlight ? "border-teal-500 ring-2 ring-teal-500/20" : "border-slate-200 dark:border-slate-800",
      )}
    >
      <header className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 pt-4 pb-3 dark:border-slate-800">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-base font-semibold">{r.switch_name}</h3>
            {highlight && <Badge tone="teal">Likely edge</Badge>}
          </div>
          <div className="mono truncate text-xs text-slate-500">
            {r.switch_host} · {r.model || "?"} · AOS {r.aos_version || "?"}
          </div>
          {r.location && <div className="truncate text-xs text-slate-500">{r.location}</div>}
        </div>
        <ClassBadge value={r.classification} confidence={r.classification_confidence} />
      </header>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 px-4 py-3 sm:grid-cols-3">
        <KV label="Port" mono>
          <span className="text-lg">{r.port || r.interface_raw}</span>
          {r.is_linkagg && <span className="ml-1 font-sans text-xs text-slate-500">(link agg)</span>}
        </KV>
        <KV label="VLAN" mono>
          <span className="text-lg">{r.vlan_id ?? "—"}</span>
        </KV>
        <KV label="Port status">
          {oper ? (
            <Badge tone={oper === "up" ? "green" : "red"} className="uppercase">
              {oper}
            </Badge>
          ) : (
            "—"
          )}
          {d.admin_status === "disabled" && <Badge tone="amber" className="ml-1">admin down</Badge>}
        </KV>
        <KV label="Untagged VLAN" mono>{r.untagged_vlan ?? "None"}</KV>
        <KV label="Tagged VLANs" mono>
          {r.tagged_vlans.length ? (
            <span title={r.tagged_vlans.join(", ")}>
              {r.tagged_vlans.slice(0, 6).join(", ")}
              {r.tagged_vlans.length > 6 && ` +${r.tagged_vlans.length - 6}`}
            </span>
          ) : (
            "None"
          )}
        </KV>
        <KV label="MACs on port" mono>{r.mac_count_on_port ?? "—"}</KV>
        <KV label="MAC type">{r.mac_type || "—"}</KV>
        <KV label="Speed">{fmtSpeed(d.speed_mbps)}</KV>
        <KV label="Description">{d.alias ? <span className="text-sm">{d.alias}</span> : "—"}</KV>
      </dl>

      <div className="mx-4 mb-3 flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600 dark:bg-slate-800/60 dark:text-slate-300">
        <Radio className="h-3.5 w-3.5 shrink-0" />
        {neighbor ? (
          <span className="truncate">
            LLDP: <span className="font-semibold">{neighbor.system_name || neighbor.chassis_id}</span>
            {neighbor.capabilities.length > 0 && ` (${neighbor.capabilities.join(", ")})`}
            {neighbor.management_ip && <span className="mono"> · {neighbor.management_ip}</span>}
          </span>
        ) : r.lldp ? (
          <span>LLDP: no neighbor detected</span>
        ) : (
          <span>LLDP: not queried</span>
        )}
      </div>

      {trunkish && (
        <div className="mx-4 mb-3 rounded-lg border border-orange-300 bg-orange-50 px-3 py-2 text-xs text-orange-900 dark:border-orange-500/40 dark:bg-orange-500/10 dark:text-orange-200">
          This looks like an uplink/trunk. The MAC is probably learned through it rather than connected to it.
        </div>
      )}

      <footer className="mt-auto flex items-center justify-between gap-2 border-t border-slate-100 px-4 py-3 dark:border-slate-800">
        <span className="text-[11px] text-slate-500">Profile {r.profile_key || "—"}</span>
        <div className="flex gap-2">
          <Button size="sm" icon={<Info className="h-3.5 w-3.5" />} onClick={onDetails}>
            View details
          </Button>
          {eligibility.allowed ? (
            <Button size="sm" variant={trunkish ? "warning" : "danger"} icon={<Power className="h-3.5 w-3.5" />} onClick={onRestart}>
              Restart port
            </Button>
          ) : (
            user?.role !== "readonly" && <span className="max-w-44 text-right text-[11px] leading-tight text-slate-500">{eligibility.reason}</span>
          )}
        </div>
      </footer>
    </article>
  );
}
