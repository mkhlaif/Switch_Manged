// Thin fetch wrapper: same-origin cookies, CSRF header on state-changing requests,
// and the backend's structured error model ({error: {code, title, message, action}}).

export class ApiError extends Error {
  status: number;
  code: string;
  title: string;
  action?: string;
  details?: Record<string, unknown>;

  constructor(status: number, body: { code?: string; title?: string; message?: string; action?: string; details?: Record<string, unknown> }) {
    super(body.message || "Request failed");
    this.status = status;
    this.code = body.code || "ERROR";
    this.title = body.title || "Request failed";
    this.action = body.action;
    this.details = body.details;
  }
}

let csrfToken = "";
let onUnauthorized: (() => void) | null = null;

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

function readCookie(name: string): string {
  const match = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return match ? decodeURIComponent(match.split("=")[1]) : "";
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function buildUrl(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken || readCookie("netops_csrf");
  let resp: Response;
  try {
    resp = await fetch(buildUrl(path, query), {
      method,
      headers,
      credentials: "same-origin",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, {
      code: "NETWORK",
      title: "Server unreachable",
      message: "The application server could not be reached. Check your connection.",
    });
  }
  if (resp.status === 204) return undefined as T;
  let data: unknown = null;
  const text = await resp.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!resp.ok) {
    const err = (data as { error?: Record<string, string> } | null)?.error || {};
    if (resp.status === 401 && onUnauthorized && !path.startsWith("/api/auth/login")) onUnauthorized();
    throw new ApiError(resp.status, err);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, query?: Query) => request<T>("GET", path, undefined, query),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  del: <T>(path: string) => request<T>("DELETE", path),
};
