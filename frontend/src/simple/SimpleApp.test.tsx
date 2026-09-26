import { StrictMode } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const post = vi.fn();
const get = vi.fn();

vi.mock("../api/client", () => ({
  api: { post: (...a: unknown[]) => post(...a), get: (...a: unknown[]) => get(...a) },
  ApiError: class extends Error {},
}));
vi.mock("../auth/AuthContext", () => ({
  useAuth: () => ({ user: { username: "test-macop", full_name: "Test Operator", role: "mac_operator" }, logout: vi.fn() }),
}));

import SimpleApp from "./SimpleApp";

// Words a non-technical user must never see (§61, §74).
const TECHNICAL = /\b(vlan|port\s*\d|1\/1\/|lldp|ssh|aos|cli|trunk|interfaces|10\.\d+\.)/i;

async function search(mac = "00:11:22:33:44:55") {
  fireEvent.change(screen.getByLabelText("Enter MAC Address"), { target: { value: mac } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /search/i }));
  });
}

beforeEach(() => {
  post.mockReset();
  get.mockReset();
});
afterEach(() => cleanup());

describe("SimpleApp (MAC_OPERATOR)", () => {
  it("shows only the switch name and a restart button when the device is found", async () => {
    post.mockResolvedValueOnce({ state: "searching", message: "Searching…", search_id: "s-1" });
    get.mockResolvedValueOnce({ state: "found", message: "Device Found", switch_name: "SW-ACCESS-37", can_restart: true });
    render(<SimpleApp />);
    await search();
    expect(await screen.findByText("SW-ACCESS-37")).toBeTruthy();
    expect(screen.getByText("Device Found")).toBeTruthy();
    expect(screen.getByRole("button", { name: /restart device/i })).toBeTruthy();
    expect(post).toHaveBeenCalledWith("/api/simple/search", { mac: "00:11:22:33:44:55" });
    expect(document.body.textContent).not.toMatch(TECHNICAL);
  });

  it("asks a simple confirmation without typing, then reports success", async () => {
    post.mockResolvedValueOnce({ state: "searching", message: "", search_id: "s-1" });
    get.mockResolvedValueOnce({ state: "found", message: "Device Found", switch_name: "SW-1", can_restart: true });
    render(<SimpleApp />);
    await search();
    fireEvent.click(await screen.findByRole("button", { name: /restart device/i }));
    expect(screen.getByText("Restart Device?")).toBeTruthy();
    expect(screen.getByText("This may temporarily disconnect the device.")).toBeTruthy();
    expect(screen.queryByRole("textbox", { name: /confirm/i })).toBeNull();

    // Cancel closes the dialog and sends nothing.
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText("Restart Device?")).toBeNull();
    expect(post).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: /restart device/i }));
    post.mockResolvedValueOnce({ state: "running", message: "", request_id: "r-1" });
    get.mockResolvedValueOnce({ state: "success", message: "Device restarted successfully." });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Restart" }));
    });
    expect(await screen.findByText("Device restarted successfully.")).toBeTruthy();
    // The client never sends a switch, port or command: only the server-side search id.
    expect(post).toHaveBeenLastCalledWith("/api/simple/restart", { search_id: "s-1" });
    expect(document.body.textContent).not.toMatch(TECHNICAL);
  });

  it("polls correctly under React StrictMode (mount, unmount, mount)", async () => {
    post.mockResolvedValueOnce({ state: "searching", message: "", search_id: "s-9" });
    get.mockResolvedValueOnce({ state: "found", message: "Device Found", switch_name: "SW-9", can_restart: true });
    render(
      <StrictMode>
        <SimpleApp />
      </StrictMode>,
    );
    await search();
    expect(await screen.findByText("SW-9")).toBeTruthy();
    expect(get).toHaveBeenCalledWith("/api/simple/search/s-9");
  });

  it("offers no restart when the backend says it is not safe", async () => {
    post.mockResolvedValueOnce({ state: "searching", message: "", search_id: "s-2" });
    get.mockResolvedValueOnce({ state: "found", message: "Device Found", switch_name: "SW-2", can_restart: false });
    render(<SimpleApp />);
    await search();
    expect(await screen.findByText("This device cannot be restarted automatically. Please contact IT support.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /restart device/i })).toBeNull();
  });

  it.each([
    [{ state: "not_found", message: "Device Not Found. Please check the MAC address and try again." }],
    [{ state: "multiple", message: "Multiple locations detected. Please contact IT support." }],
  ])("shows the backend's plain message (%o)", async (result) => {
    post.mockResolvedValueOnce({ state: "searching", message: "", search_id: "s-3" });
    get.mockResolvedValueOnce(result);
    render(<SimpleApp />);
    await search();
    expect(await screen.findByText(result.message)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /restart device/i })).toBeNull();
  });

  it("never shows technical errors", async () => {
    post.mockRejectedValueOnce(new Error("SSH timeout on 10.1.2.3: AOS parser failed"));
    render(<SimpleApp />);
    await search();
    await waitFor(() => expect(screen.getByText("Something went wrong. Please try again or contact IT support.")).toBeTruthy());
    expect(document.body.textContent).not.toMatch(TECHNICAL);
  });

  it("reports a failed restart in plain language", async () => {
    post.mockResolvedValueOnce({ state: "searching", message: "", search_id: "s-4" });
    get.mockResolvedValueOnce({ state: "found", message: "Device Found", switch_name: "SW-4", can_restart: true });
    render(<SimpleApp />);
    await search();
    fireEvent.click(await screen.findByRole("button", { name: /restart device/i }));
    post.mockResolvedValueOnce({ state: "blocked", message: "This device cannot be restarted automatically. Please contact IT support." });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Restart" }));
    });
    expect(await screen.findByText("This device cannot be restarted automatically. Please contact IT support.")).toBeTruthy();
  });
});
