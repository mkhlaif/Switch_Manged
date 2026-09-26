import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { SafetyIndicator, SafetyResponse, SettingsResponse } from "../api/types";

export interface SafetyFlags {
  dryRun: boolean;
  lab: boolean;
  unknownKeys: boolean;
  firewallReady: boolean;
  indicator: SafetyIndicator;
  mode: string;
  modeReason: string;
  killSwitch: boolean;
  killSwitchEnv: boolean;
  readOnlyEnv: boolean;
  safeMode: boolean;
  safeModeReason: string;
  blockReason: string | null;
}

export function flagsFrom(settings: SettingsResponse | null, safety: SafetyResponse): SafetyFlags {
  const s = safety.state;
  return {
    dryRun: Boolean(settings?.values.dry_run_mode ?? s.dry_run_mode),
    lab: Boolean(settings?.environment.enable_simulator),
    unknownKeys: Boolean(settings?.environment.ssh_allow_unknown_host_keys),
    firewallReady: safety.firewall.ready,
    indicator: safety.indicator,
    mode: s.mode,
    modeReason: s.mode_reason,
    killSwitch: !s.command_execution_enabled,
    killSwitchEnv: s.kill_switch_forced_by_env,
    readOnlyEnv: s.read_only_forced_by_env,
    safeMode: s.safe_mode,
    safeModeReason: s.safe_mode_reason,
    blockReason: s.state_changing_block_reason,
  };
}

/** Live safety state for the always-visible indicator (§44). Refreshes every 15 s and on the
 * "settings-changed" window event. */
export function useSafetyFlags() {
  const [flags, setFlags] = useState<SafetyFlags | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      Promise.all([api.get<SettingsResponse>("/api/settings").catch(() => null), api.get<SafetyResponse>("/api/safety")])
        .then(([settings, safety]) => alive && setFlags(flagsFrom(settings, safety)))
        .catch(() => undefined);
    load();
    window.addEventListener("settings-changed", load);
    const timer = window.setInterval(load, 15000);
    return () => {
      alive = false;
      window.removeEventListener("settings-changed", load);
      window.clearInterval(timer);
    };
  }, []);
  return flags;
}

export function notifySafetyChanged() {
  window.dispatchEvent(new Event("settings-changed"));
}

export const INDICATOR_STYLE: Record<SafetyIndicator, { label: string; className: string; description: string }> = {
  ACTIVE: {
    label: "NETWORK SAFETY: ACTIVE",
    className: "bg-amber-500 text-slate-950",
    description: "MAINTENANCE mode: authorized, fully checked state-changing operations are enabled.",
  },
  "READ ONLY": {
    label: "READ ONLY",
    className: "bg-sky-600 text-white",
    description: "No state-changing operations. Searches and read-only checks continue.",
  },
  "SAFE MODE": {
    label: "SAFE MODE",
    className: "bg-red-600 text-white",
    description: "Circuit breaker tripped: state changes blocked until an administrator resets it.",
  },
  STOPPED: {
    label: "ALL NETWORK OPERATIONS STOPPED",
    className: "bg-red-700 text-white",
    description: "Kill switch engaged: every state-changing command is blocked.",
  },
  EMERGENCY: {
    label: "EMERGENCY MODE",
    className: "bg-fuchsia-700 text-white",
    description: "Only administrator-approved emergency operations are allowed.",
  },
};
