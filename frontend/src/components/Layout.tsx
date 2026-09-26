import { Bell, FileClock, FlaskConical, History, LayoutDashboard, LogOut, Moon, Network, Power, Search, Server, Settings, Share2, ShieldAlert, ShieldCheck, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api/client";
import type { AlertSummary } from "../api/types";
import { useAuth, type Permission } from "../auth/AuthContext";
import { useInterval, useTheme } from "../lib/hooks";
import { useSafetyFlags } from "../lib/safety";
import { SafetyIndicatorBadge } from "./SafetyIndicator";
import { Badge, cx } from "./ui";

export { useSafetyFlags } from "../lib/safety";

interface NavItem {
  to: string;
  label: string;
  icon: typeof Search;
  end?: boolean;
  permission: Permission;
}

export const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true, permission: "view_dashboard" },
  { to: "/mac-search", label: "MAC Search", icon: Search, permission: "mac_search" },
  { to: "/switches", label: "Switches", icon: Server, permission: "view_inventory" },
  { to: "/topology", label: "Topology", icon: Share2, permission: "view_inventory" },
  { to: "/alerts", label: "Alerts", icon: Bell, permission: "view_alerts" },
  { to: "/history", label: "Search History", icon: History, permission: "view_history" },
  { to: "/port-actions", label: "Port Actions", icon: Power, permission: "view_port_actions" },
  { to: "/safety", label: "Safety Controls", icon: ShieldAlert, permission: "view_safety" },
  { to: "/audit", label: "Audit Logs", icon: FileClock, permission: "view_audit" },
  { to: "/settings", label: "Settings", icon: Settings, permission: "view_settings" },
];

export function visibleNav(can: (p: Permission) => boolean): NavItem[] {
  return NAV.filter((n) => can(n.permission));
}

function useOpenAlerts(enabled: boolean) {
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const load = () => {
    if (enabled) api.get<AlertSummary>("/api/alerts/summary").then(setSummary).catch(() => undefined);
  };
  useEffect(load, [enabled]); // eslint-disable-line react-hooks/exhaustive-deps
  useInterval(load, 30000, enabled);
  return summary;
}

export default function Layout() {
  const { user, logout, can } = useAuth();
  const [dark, toggleTheme] = useTheme();
  const flags = useSafetyFlags();
  const nav = visibleNav(can);
  const alerts = useOpenAlerts(can("view_alerts"));
  const urgent = alerts ? alerts.by_severity.CRITICAL + alerts.by_severity.HIGH : 0;

  return (
    <div className="flex h-full">
      <aside className="hidden w-64 shrink-0 flex-col bg-slate-900 text-slate-300 md:flex">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-600 text-white shadow-sm">
            <Network className="h-5 w-5" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-white">Network Operations</div>
            <div className="text-[11px] text-slate-400">OmniSwitch · AOS · Safety platform</div>
          </div>
        </div>
        <div className="px-3 pb-3">
          <SafetyIndicatorBadge indicator={flags?.indicator ?? null} />
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100",
                )
              }
            >
              <Icon className="h-4 w-4" />
              <span className="flex-1">{label}</span>
              {to === "/alerts" && alerts && alerts.open > 0 && (
                <span className={cx("rounded-full px-1.5 text-[11px] font-bold tnum", urgent ? "bg-red-600 text-white" : "bg-slate-700 text-slate-200")}>{alerts.open}</span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 p-3 text-xs text-slate-500">
          <div className="flex items-center gap-2 px-2 py-1">
            <ShieldCheck className="h-3.5 w-3.5 text-teal-500" /> Read first · Analyze · Change last
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-slate-200 bg-white/80 px-4 backdrop-blur dark:border-slate-800 dark:bg-slate-900/80 md:px-6">
          <nav className="flex gap-1 overflow-x-auto md:hidden">
            {nav.map(({ to, icon: Icon, end, label }) => (
              <NavLink key={to} to={to} end={end} aria-label={label} className={({ isActive }) => cx("rounded-md p-2", isActive ? "bg-teal-50 text-teal-700 dark:bg-teal-500/10" : "text-slate-500")}>
                <Icon className="h-4 w-4" />
              </NavLink>
            ))}
          </nav>
          <div className="flex flex-wrap items-center gap-2">
            <div className="md:hidden">
              <SafetyIndicatorBadge indicator={flags?.indicator ?? null} compact />
            </div>
            {flags && !flags.firewallReady && (
              <Badge tone="red" className="uppercase">
                <ShieldAlert className="h-3 w-3" /> Safety firewall failed — all commands blocked
              </Badge>
            )}
            {flags && (
              <span className="hidden text-xs text-slate-500 lg:inline">
                Mode <span className="font-semibold text-slate-700 dark:text-slate-200">{flags.mode}</span>
                {flags.dryRun && <> · <span className="font-semibold text-sky-700 dark:text-sky-400">dry run</span></>}
              </span>
            )}
            {flags?.lab && (
              <Badge tone="violet" className="uppercase">
                <FlaskConical className="h-3 w-3" /> Lab mode
              </Badge>
            )}
            {flags?.unknownKeys && <Badge tone="red">Host-key checking disabled</Badge>}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={toggleTheme} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Toggle theme">
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <div className="hidden text-right leading-tight sm:block">
              <div className="text-sm font-medium">{user?.full_name || user?.username}</div>
              <div className="text-[11px] uppercase tracking-wide text-slate-500">{user?.role}</div>
            </div>
            <button onClick={logout} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800" aria-label="Sign out" title="Sign out">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto px-4 py-6 md:px-8">
          <div className="mx-auto max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
