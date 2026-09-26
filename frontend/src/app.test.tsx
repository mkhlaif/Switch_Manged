import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { MacSearchResult, Role } from "./api/types";
import type { Permission } from "./auth/AuthContext";

const get = vi.fn();
vi.mock("./api/client", () => ({
  api: { get: (...a: unknown[]) => get(...a), post: vi.fn(), put: vi.fn(), patch: vi.fn(), del: vi.fn() },
  ApiError: class extends Error {},
  setCsrfToken: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
}));

import App from "./App";
import { SafetyIndicatorBadge } from "./components/SafetyIndicator";
import { restartEligibility } from "./components/ResultCard";
import { visibleNav } from "./components/Layout";

afterEach(() => cleanup());

const READONLY: Permission[] = ["mac_search", "port_inspect", "view_inventory", "view_history", "view_port_actions", "view_dashboard", "view_alerts", "view_safety", "view_settings", "view_integrations"];

describe("interface separation (§78)", () => {
  it("renders the simplified screen for a MAC_OPERATOR, without the admin navigation", async () => {
    get.mockImplementation((path: string) =>
      path === "/api/auth/me"
        ? Promise.resolve({ user: { id: 9, username: "john", full_name: "John", role: "mac_operator", interface: "simple", permissions: ["simple_restart", "simple_search"] }, csrf_token: "x" })
        : Promise.reject(new Error(`unexpected request ${path}`)),
    );
    render(<App />);
    expect(await screen.findByText("Network Device Tool")).toBeTruthy();
    expect(screen.queryByText("Dashboard")).toBeNull();
    expect(screen.queryByText("Audit Logs")).toBeNull();
    // The simplified screen never requests technical endpoints.
    expect(get.mock.calls.map((c) => c[0])).toEqual(["/api/auth/me"]);
  });

  it("filters navigation by server-provided permissions", () => {
    const readonly = visibleNav((p) => READONLY.includes(p)).map((n) => n.label);
    expect(readonly).toContain("MAC Search");
    expect(readonly).not.toContain("Audit Logs");
    expect(visibleNav(() => false)).toEqual([]);
    expect(visibleNav(() => true).map((n) => n.label)).toContain("Safety Controls");
  });
});

describe("safety indicator (§43)", () => {
  it.each([
    ["ACTIVE", "● ACTIVE"],
    ["READ ONLY", "● READ ONLY"],
    ["SAFE MODE", "⚠ SAFE MODE"],
    ["STOPPED", "● STOPPED"],
  ] as const)("shows %s", (indicator, text) => {
    render(<SafetyIndicatorBadge indicator={indicator} />);
    const el = screen.getByTestId("safety-indicator");
    expect(el.textContent).toContain("Network safety");
    expect(el.textContent?.replace(/\s+/g, " ")).toContain(text);
  });
});

describe("restart eligibility hints", () => {
  const base = { port: "1/1/24", is_linkagg: false, classification: "ACCESS" } as MacSearchResult;
  const check = (role: Role, cls: string) => restartEligibility({ ...base, classification: cls } as MacSearchResult, role);

  it("never offers a restart for uncertain ports or non-technical roles", () => {
    expect(check("admin", "UNKNOWN").allowed).toBe(false);
    expect(check("mac_operator", "ACCESS").allowed).toBe(false);
    expect(check("readonly", "ACCESS").allowed).toBe(false);
    expect(check("operator", "TRUNK").allowed).toBe(false);
    expect(check("operator", "ACCESS").allowed).toBe(true);
  });

  it("marks the admin trunk override as EMERGENCY-only", () => {
    const r = check("admin", "LIKELY_TRUNK");
    expect(r.allowed).toBe(true);
    expect(r.reason).toContain("EMERGENCY");
  });
});
