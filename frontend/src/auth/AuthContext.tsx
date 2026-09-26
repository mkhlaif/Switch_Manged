import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthorizedHandler } from "../api/client";
import type { Role, User } from "../api/types";

// UI hints only: every permission is enforced again by the backend on every request.
export type Permission =
  | "mac_search"
  | "port_inspect"
  | "view_inventory"
  | "view_history"
  | "view_port_actions"
  | "view_dashboard"
  | "view_alerts"
  | "view_safety"
  | "view_settings"
  | "view_integrations"
  | "test_switch"
  | "restart_port"
  | "ack_alerts"
  | "stop_operations"
  | "simple_search"
  | "simple_restart"
  | "view_audit"
  | "manage_inventory"
  | "manage_credentials"
  | "manage_users"
  | "manage_profiles"
  | "manage_safety"
  | "emergency_actions";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (role: Role) => boolean;
  can: (permission: Permission) => boolean;
  simple: boolean;
}

// Technical roles form a ladder; MAC_OPERATOR is outside it (separate, minimal permission set).
const RANK: Record<Role, number> = { mac_operator: -1, readonly: 0, operator: 1, admin: 2 };
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    api
      .get<{ user: User; csrf_token: string }>("/api/auth/me")
      .then((r) => {
        setCsrfToken(r.csrf_token);
        setUser(r.user);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const r = await api.post<{ user: User; csrf_token: string }>("/api/auth/login", { username, password });
    setCsrfToken(r.csrf_token);
    setUser(r.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      setCsrfToken("");
      setUser(null);
    }
  }, []);

  const hasRole = useCallback(
    (role: Role) => !!user && user.role !== "mac_operator" && RANK[user.role] >= RANK[role],
    [user],
  );
  const can = useCallback((permission: Permission) => !!user?.permissions?.includes(permission), [user]);
  const simple = user?.interface === "simple" || user?.role === "mac_operator";

  const value = useMemo(
    () => ({ user, loading, login, logout, hasRole, can, simple }),
    [user, loading, login, logout, hasRole, can, simple],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
