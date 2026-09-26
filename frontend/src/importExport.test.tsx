// Bulk switch import dialog and the admin-only import/export controls.
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const get = vi.fn();
const post = vi.fn();
let role = "admin";

vi.mock("./api/client", () => ({
  api: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a), put: vi.fn(), patch: vi.fn(), del: vi.fn() },
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
    can: () => true,
  }),
}));

import { ImportDialog } from "./components/ImportDialog";
import SwitchesPage from "./pages/SwitchesPage";

const PREVIEW = {
  id: "job-1",
  status: "validated",
  file_format: "csv",
  filename: "switches.csv",
  created_by: "test-admin",
  on_existing: "skip",
  skip_invalid: false,
  cancel_requested: false,
  total: 4,
  valid: 2,
  invalid: 1,
  duplicates: 1,
  warnings: 0,
  processed: 0,
  imported: 0,
  updated: 0,
  unchanged: 0,
  skipped: 0,
  failed: 0,
  new: 2,
  existing_changed: 0,
  existing_unchanged: 0,
  file_errors: [],
  error: "",
  created_at: null,
  expires_at: null,
  confirmed_at: null,
  started_at: null,
  completed_at: null,
  failed_at: null,
  rows: [
    { line: 2, name: "SW-1", management_ip: "10.0.0.1", status: "valid", action: "create", errors: [], warnings: [], diff: [], result: "", message: "" },
    { line: 3, name: "SW-2", management_ip: "10.0.0.2", status: "valid", action: "create", errors: [], warnings: [], diff: [], result: "", message: "" },
    { line: 4, name: "BAD", management_ip: "x", status: "invalid", action: "", errors: ["management_ip 'x' is not a valid IPv4/IPv6 address."], warnings: [], diff: [], result: "", message: "" },
    { line: 5, name: "SW-1", management_ip: "10.0.0.1", status: "duplicate", action: "skip", errors: [], warnings: ["Identical to line 2; skipped."], diff: [], result: "", message: "" },
  ],
};

function pickFile(content: string, name = "switches.csv") {
  const file = new File([content], name, { type: "text/csv" });
  fireEvent.change(screen.getByLabelText("Import file"), { target: { files: [file] } });
}

beforeEach(() => {
  get.mockReset();
  post.mockReset();
  role = "admin";
});
afterEach(() => cleanup());

describe("import dialog", () => {
  it("validates, previews, requires acknowledging invalid rows, then imports", async () => {
    post.mockResolvedValueOnce(PREVIEW);
    const onImported = vi.fn();
    render(<ImportDialog onClose={vi.fn()} onImported={onImported} />);
    pickFile("name,management_ip,model,aos_version\nSW-1,10.0.0.1,OS6360,8.10R1\n");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /validate file/i }));
    });
    expect(post).toHaveBeenCalledWith("/api/switches/import/validate", {
      filename: "switches.csv",
      format: "csv",
      content: "name,management_ip,model,aos_version\nSW-1,10.0.0.1,OS6360,8.10R1\n",
    });
    expect(screen.getByTestId("import-valid").textContent).toBe("2");
    expect(screen.getByTestId("import-invalid").textContent).toBe("1");
    expect(screen.getByText("management_ip 'x' is not a valid IPv4/IPv6 address.")).toBeTruthy();

    const confirm = screen.getByRole("button", { name: /confirm import of 2 switches/i }) as HTMLButtonElement;
    // Default mode is all-or-nothing: a file with an invalid row can never be imported.
    expect(confirm.disabled).toBe(true);
    expect(screen.getByText("The file has invalid rows")).toBeTruthy();
    expect(screen.queryByLabelText(/skip the 2 invalid\/duplicate rows/i)).toBeNull();
    // Row-by-row is an explicit choice, and skipping must still be acknowledged.
    fireEvent.change(screen.getByLabelText("Import mode"), { target: { value: "per_row" } });
    expect(confirm.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/skip the 2 invalid\/duplicate rows/i));
    expect(confirm.disabled).toBe(false);

    post.mockResolvedValueOnce({ ...PREVIEW, status: "queued" });
    get.mockResolvedValueOnce({ ...PREVIEW, rows: undefined, status: "completed", processed: 4, imported: 2, skipped: 2 });
    get.mockResolvedValueOnce({ ...PREVIEW, status: "completed", processed: 4, imported: 2, skipped: 2 });
    await act(async () => {
      fireEvent.click(confirm);
    });
    expect(post).toHaveBeenLastCalledWith("/api/switches/import/job-1/confirm", { on_existing: "skip", skip_invalid: true, mode: "per_row" });
    await waitFor(() => expect(screen.getByTestId("import-imported").textContent).toBe("2"));
    expect(get).toHaveBeenCalledWith("/api/switches/import/job-1", { rows: false });
    expect(onImported).toHaveBeenCalled();
  });

  it("rejects files larger than 5 MB before uploading", async () => {
    render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
    pickFile("x".repeat(5_000_001));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /validate file/i }));
    });
    expect(post).not.toHaveBeenCalled();
    expect(screen.getByText(/larger than 5 MB/)).toBeTruthy();
  });

  it("shows file-level rejections such as password columns", async () => {
    post.mockResolvedValueOnce({ ...PREVIEW, status: "failed", valid: 0, invalid: 0, duplicates: 0, total: 0, rows: [], file_errors: ["The file contains secret-like column(s) password."] });
    render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
    pickFile("name,management_ip,model,aos_version,password\n");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /validate file/i }));
    });
    expect(screen.getByText("The file was rejected")).toBeTruthy();
    expect((screen.getByRole("button", { name: /confirm import/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("switches page controls", () => {
  it("offers import and export to administrators only", async () => {
    get.mockResolvedValue([]);
    render(
      <MemoryRouter>
        <SwitchesPage />
      </MemoryRouter>,
    );
    expect(await screen.findByRole("button", { name: "Import" })).toBeTruthy();
    expect(screen.getByText("Export CSV").closest("a")?.getAttribute("href")).toBe("/api/switches/export?format=csv");
    expect(screen.getByText("Export JSON").closest("a")?.getAttribute("href")).toBe("/api/switches/export?format=json");
    cleanup();

    role = "operator";
    render(
      <MemoryRouter>
        <SwitchesPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(get).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Import" })).toBeNull();
    expect(screen.queryByText("Export CSV")).toBeNull();
  });
});
