const MAC_PATTERNS = [
  /^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/,
  /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/,
  /^[0-9a-f]{12}$/,
];

/** Mirrors the backend normalization. Returns 12 hex chars or null. */
export function normalizeMac(value: string): string | null {
  const v = value.trim().toLowerCase();
  if (!MAC_PATTERNS.some((p) => p.test(v))) return null;
  return v.replace(/[^0-9a-f]/g, "");
}

export function formatMac(mac: string): string {
  const m = mac.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  if (m.length !== 12) return mac;
  return m.match(/.{2}/g)!.join(":");
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 45) return "just now";
  if (diff < 3600) return `${Math.round(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`;
  return `${Math.round(diff / 86400)} d ago`;
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export function fmtSpeed(mbps: number | null | undefined): string {
  if (!mbps) return "—";
  return mbps >= 1000 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`;
}

export function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
