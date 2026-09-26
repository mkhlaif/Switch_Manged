// Automatic discovery in the UI: nobody types a model or AOS version, the identity comes from
// discovery, and a mismatch can only be accepted by an administrator with an audited reason.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const get = vi.fn();
const post = vi.fn();
const patch = vi.fn();
let role = "admin";

vi.mock("./api/client", () => ({
  api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a), put: vi.fn(), patch: (...a: unknown[]) => patch(...a), del: vi.fn() },
  ApiError: class extends Error {},
  buildUrl: (p: string) => p,
}));
vi.mock("./auth/AuthContext", () => ({
  useAuth: () => ({
    user: { username: "test-admin", role },
    hasRole: (r: string) => {
      const rank: Record<string, number> = { readonly: 0, operator: 1, admin: 2 };
      return rank[role] >= rank[r];
    },
    can: () => false,
  }),
}));
vi.mock("./lib/safety", () => ({ useSafetyFlags: () => ({ lab: false }) }));

import { SwitchForm } from "./components/SwitchForm";
import SwitchDetailPage from "./pages/SwitchDetailPage";

const SWITCH = {
  id: 7,
  name: "SW-ACCESS-07",
  host: "10.0.0.7",
  hostname: "",
  ssh_port: 22,
  vendor: "ALE",
  model: "OS6860E-P24",
  aos_version: "8.10.94.R03",
  discovery_status: "mismatch",
  discovery_error: "AOS version changed from 8.9.221.R03 to 8.10.94.R03",
  discovery_category: "SAFETY_CHECK_FAILED",
  discovery_profile: "ALE_AOS8_SHOW_SYSTEM",
  discovered_at: "2026-09-26T10:00:00Z",
  system_name: "SW-ACCESS-07",
  system_object_id: "1.3.6.1.4.1.6486.801",
  expected_model: "",
  expected_aos_version: "",
  expected_host_key_fingerprint: "",
  environment: "production",
  site: "",
  location: "",
  description: "",
  enabled: true,
  credential_id: 1,
  credential_name: "ro",
  profile_key: "",
  effective_profile: "AOS8",
  profile_reason: "",
  transport: "ssh",
  legacy_ssh_algorithms: false,
  uplink_ports: [],
  port_locations: {},
  role: "access",
  host_key_fingerprint: "SHA256:x",
  host_key_trusted: true,
  status: "online",
  last_check_at: null,
  last_success_at: null,
  last_error: "",
  created_at: "2026-09-26T10:00:00Z",
  updated_at: "2026-09-26T10:00:00Z",
};

beforeEach(() => {
  get.mockReset();
  post.mockReset();
  patch.mockReset();
  role = "admin";
});
afterEach(() => cleanup());

describe("switch form", () => {
  it("never asks for model or AOS version; expected values are optional metadata", async () => {
    get.mockImplementation((url: string) => Promise.resolve(url === "/api/credentials" ? [] : { profiles: [] }));
    post.mockResolvedValue({ ...SWITCH, id: 9 });
    const onSaved = vi.fn();
    await act(async () => {
      render(<SwitchForm labMode={false} onClose={vi.fn()} onSaved={onSaved} />);
    });
    expect(screen.queryByLabelText(/^model$/i)).toBeNull();
    expect(screen.queryByLabelText(/^AOS version$/i)).toBeNull();
    expect(screen.getByText(/discovered automatically/i)).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "SW-NEW" } });
    fireEvent.change(screen.getByLabelText(/management ip/i), { target: { value: "10.0.0.9" } });
    fireEvent.change(screen.getByLabelText(/expected model/i), { target: { value: "OS6360" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /save/i }));
    });
    const [, body] = post.mock.calls[0];
    expect(body).toMatchObject({ name: "SW-NEW", host: "10.0.0.9", expected_model: "OS6360", environment: "production" });
    expect(body).not.toHaveProperty("model");
    expect(body).not.toHaveProperty("aos_version");
    expect(onSaved).toHaveBeenCalled();
  });
});

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={["/switches/7"]}>
      <Routes>
        <Route path="/switches/:id" element={<SwitchDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("switch identity", () => {
  it("shows a mismatch and lets an administrator accept it with a reason", async () => {
    get.mockResolvedValue(SWITCH);
    post.mockResolvedValue({ ...SWITCH, discovery_status: "discovered", discovery_error: "" });
    renderDetail();
    await waitFor(() => expect(screen.getByText("Identity mismatch")).toBeTruthy());
    expect(screen.getByText("State-changing operations are blocked")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /review and accept identity/i }));
    const accept = screen.getByRole("button", { name: /^accept identity$/i }) as HTMLButtonElement;
    expect(accept.disabled).toBe(true); // a reason is mandatory
    fireEvent.change(screen.getByLabelText(/reason/i), { target: { value: "AOS upgrade CHG-42" } });
    await act(async () => {
      fireEvent.click(accept);
    });
    expect(post).toHaveBeenCalledWith("/api/switches/7/discovery/accept", { reason: "AOS upgrade CHG-42" });
    await waitFor(() => expect(screen.queryByText("Identity mismatch")).toBeNull());
    expect(screen.queryByText("State-changing operations are blocked")).toBeNull();
  });

  it("offers no identity actions to operators", async () => {
    role = "operator";
    get.mockResolvedValue(SWITCH);
    renderDetail();
    await waitFor(() => expect(screen.getByText("Identity mismatch")).toBeTruthy());
    expect(screen.queryByRole("button", { name: /review and accept identity/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /run discovery/i })).toBeNull();
  });
});
