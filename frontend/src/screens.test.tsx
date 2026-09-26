// Frontend tests for login, technical MAC search, restart confirmation and role restrictions.
// The backend enforces every rule independently; these tests check that the UI never offers
// more than the server allows and never sends anything but structured operations.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const get = vi.fn();
const post = vi.fn();
const login = vi.fn();
let currentUser: Record<string, unknown> | null = null;

vi.mock("./api/client", () => {
  class ApiError extends Error {
    status: number;
    code: string;
    title: string;
    constructor(status: number, body: { message?: string; code?: string; title?: string }) {
      super(body.message || "Request failed");
      this.status = status;
      this.code = body.code || "ERROR";
      this.title = body.title || "Request failed";
    }
  }
  return {
    api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a), put: vi.fn(), patch: vi.fn(), del: vi.fn() },
    ApiError,
    setCsrfToken: vi.fn(),
    setUnauthorizedHandler: vi.fn(),
    buildUrl: (p: string) => p,
  };
});
vi.mock("./auth/AuthContext", () => ({
  useAuth: () => ({
    user: currentUser,
    login,
    logout: vi.fn(),
    loading: false,
    simple: false,
    hasRole: (r: string) => {
      const rank: Record<string, number> = { readonly: 0, operator: 1, admin: 2 };
      return !!currentUser && currentUser.role !== "mac_operator" && rank[currentUser.role as string] >= rank[r];
    },
    can: (p: string) => ((currentUser?.permissions as string[]) || []).includes(p),
  }),
}));

import { ApiError } from "./api/client";
import { MacSearchBox } from "./components/MacSearchBox";
import { RestartDialog } from "./components/RestartDialog";
import { visibleNav } from "./components/Layout";
import LoginPage from "./pages/LoginPage";

beforeEach(() => {
  get.mockReset();
  post.mockReset();
  login.mockReset();
  currentUser = null;
});
afterEach(() => cleanup());

describe("login", () => {
  it("submits the credentials and shows the server's error without technical details", async () => {
    login.mockRejectedValueOnce(new ApiError(401, { message: "Invalid username or password.", code: "INVALID_CREDENTIALS" }));
    render(<LoginPage />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong-password" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    });
    expect(login).toHaveBeenCalledWith("alice", "wrong-password");
    expect(await screen.findByText("Invalid username or password.")).toBeTruthy();
    // The password field is cleared after a failed attempt.
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
  });
});

describe("technical MAC search", () => {
  it("rejects invalid MACs in the UI and sends only a structured request", async () => {
    post.mockResolvedValueOnce({ id: "s-1" });
    const started = vi.fn();
    render(<MacSearchBox onStarted={started} />);
    const input = screen.getByPlaceholderText(/00:11:22:33:44:55/);
    fireEvent.change(input, { target: { value: "00:11:22:33:44:55;reload" } });
    expect(screen.getByText("Not a valid MAC address.")).toBeTruthy();
    expect((screen.getByRole("button", { name: /search mac/i }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(input, { target: { value: "0011.2233.4455" } });
    expect(screen.getByText("00:11:22:33:44:55")).toBeTruthy(); // normalized preview
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /search mac/i }));
    });
    expect(post).toHaveBeenCalledWith("/api/mac/search", { mac: "0011.2233.4455", mode: "STANDARD" });
    expect(started).toHaveBeenCalledWith("s-1");
  });

  it("requires an explicit small switch selection for DEEP mode", async () => {
    get.mockResolvedValueOnce([
      { id: 1, name: "SW-A", enabled: true },
      { id: 2, name: "SW-B", enabled: true },
    ]);
    render(<MacSearchBox onStarted={vi.fn()} />);
    fireEvent.change(screen.getByPlaceholderText(/00:11:22:33:44:55/), { target: { value: "001122334455" } });
    fireEvent.click(screen.getByRole("radio", { name: /deep/i }));
    const submit = screen.getByRole("button", { name: /search mac/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.click(await screen.findByLabelText("SW-A"));
    expect(submit.disabled).toBe(false);
  });
});

describe("restart confirmation", () => {
  const plan = {
    id: 7,
    plan_token: "t-7",
    status: "planned",
    available: true,
    execution_allowed: false,
    execution_note: "dry run",
    dry_run: true,
    risk_level: "normal",
    required_phrases: ["RESTART PORT 1/1/24"],
    warnings: ["This operation will temporarily disconnect the device."],
    switch_name: "SW-ACCESS-01",
    port: "1/1/24",
    mac: "001122334455",
    vlan_id: 206,
    classification: "ACCESS",
    classification_confidence: "High",
    classification_reasons: [],
    method: "link_bounce",
    strategy: "INTERFACE_ADMIN_STATE",
    aos_version: "8.9.221.R03",
    commands: ["interfaces port 1/1/24 admin-state disable", "interfaces port 1/1/24 admin-state enable"],
    commands_executed: [],
    steps: [],
    verification: {},
    safety_report: {},
    expires_at: new Date(Date.now() + 300000).toISOString(),
  };

  it("enables the action only after the exact phrase is typed and sends the plan token", async () => {
    post.mockResolvedValueOnce(plan);
    render(<RestartDialog target={{ searchResultId: 3, switchName: "SW-ACCESS-01" }} onClose={vi.fn()} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /re-check/i }));
    });
    const confirm = await screen.findByLabelText('Type "RESTART PORT 1/1/24" to confirm');
    const run = screen.getByRole("button", { name: /run dry run/i }) as HTMLButtonElement;
    expect(run.disabled).toBe(true);
    fireEvent.change(confirm, { target: { value: "RESTART PORT" } });
    expect(run.disabled).toBe(true);
    fireEvent.change(confirm, { target: { value: "RESTART PORT 1/1/24" } });
    expect(run.disabled).toBe(false);

    post.mockResolvedValueOnce({ ...plan, status: "dry_run" });
    await act(async () => {
      fireEvent.click(run);
    });
    expect(post).toHaveBeenLastCalledWith("/api/ports/restart", { plan_token: "t-7", confirmations: ["RESTART PORT 1/1/24"], reason: "" });
    // No request ever carries CLI text.
    for (const call of post.mock.calls) expect(JSON.stringify(call[1] ?? {})).not.toMatch(/"command"|"cli"/);
  });

  it("shows why a restart is not available (e.g. trunk port) and offers no action", async () => {
    post.mockResolvedValueOnce({ ...plan, available: false, status: "denied", required_phrases: [], blocked_reason: "PORT RESTART BLOCKED. This port appears to be a trunk/uplink. No command was executed." });
    render(<RestartDialog target={{ searchResultId: 3, switchName: "SW-ACCESS-01" }} onClose={vi.fn()} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /re-check/i }));
    });
    expect(await screen.findByText(/appears to be a trunk\/uplink/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /restart port now|run dry run/i })).toBeNull();
  });
});

describe("role restrictions in the admin interface", () => {
  const perms = {
    readonly: ["mac_search", "port_inspect", "view_inventory", "view_history", "view_port_actions", "view_dashboard", "view_alerts", "view_safety", "view_settings", "view_integrations"],
    admin: ["mac_search", "port_inspect", "view_inventory", "view_history", "view_port_actions", "view_dashboard", "view_alerts", "view_safety", "view_settings", "view_integrations", "view_audit", "manage_users", "manage_safety", "restart_port"],
  };

  it("hides audit logs from read-only users and shows the full set to admins", () => {
    const labels = (p: string[]) => visibleNav((x) => p.includes(x)).map((n) => n.label);
    expect(labels(perms.readonly)).not.toContain("Audit Logs");
    expect(labels(perms.readonly)).toContain("Topology");
    expect(labels(perms.admin)).toEqual(expect.arrayContaining(["Dashboard", "MAC Search", "Switches", "Topology", "Alerts", "Safety Controls", "Audit Logs", "Settings"]));
  });

  it("does not offer a restart button on the port page without the restart permission", async () => {
    currentUser = { id: 2, username: "reader", role: "readonly", permissions: perms.readonly };
    get.mockResolvedValue({
      switch: { id: 1, name: "SW-ACCESS-01", model: "OS6860E-P24", aos_version: "8.9.221.R03", role: "access" },
      port: "1/1/24", profile: "AOS8", mac: "001122334455", mac_on_port: true,
      details: { oper_status: "up", admin_status: "enabled" }, vlans: [], tagged_vlans: [], untagged_vlan: 206,
      lldp: [], mac_count: 1, classification: { category: "ACCESS", confidence: "High", confidence_score: 0.9, reasons: [] },
      warnings: [], commands: ["show interfaces port 1/1/24"],
    });
    const { default: PortDetailsPage } = await import("./pages/PortDetailsPage");
    render(
      <MemoryRouter initialEntries={["/port?switch=1&port=1%2F1%2F24&mac=001122334455"]}>
        <PortDetailsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Classification")).toBeTruthy());
    expect(screen.queryByRole("button", { name: /restart port/i })).toBeNull();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeTruthy();
  });
});
