// Bulk switch import (administrators): upload → server validation → preview → explicit
// confirmation → background import with progress → result → automatic discovery. Nothing is
// written to the inventory before the confirmation; the server re-checks every row while
// importing. Atomic mode (default) imports every row or none.
import { Download, FileUp, Upload } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { ImportJob, ImportRow } from "../api/types";
import { Badge, Button, ErrorBanner, Modal, Notice, Select, Table, Td, Th } from "./ui";

const MAX_BYTES = 5_000_000;
type Step = "select" | "preview" | "running" | "done";

function Stat({ label, value, tone }: { label: string; value: number; tone?: "green" | "red" | "amber" }) {
  const color = tone === "green" ? "text-emerald-700 dark:text-emerald-400" : tone === "red" ? "text-red-700 dark:text-red-400" : tone === "amber" ? "text-amber-700 dark:text-amber-400" : "";
  return (
    <div className="rounded-lg border border-slate-200 px-3 py-2 dark:border-slate-800">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`text-lg font-semibold tabular-nums ${color}`} data-testid={`import-${label.toLowerCase().replace(/\s+/g, "-")}`}>
        {value}
      </div>
    </div>
  );
}

function RowStatus({ row }: { row: ImportRow }) {
  if (row.result) {
    const tone = row.result === "imported" || row.result === "updated" ? "green" : row.result === "failed" || row.result === "rolled_back" ? "red" : "slate";
    return <Badge tone={tone}>{row.result.replace("_", " ")}</Badge>;
  }
  if (row.status === "invalid") return <Badge tone="red">invalid</Badge>;
  if (row.status === "duplicate") return <Badge tone="amber">duplicate</Badge>;
  return <Badge tone={row.action === "create" ? "green" : row.action === "update" ? "amber" : "slate"}>{row.action === "create" ? "new" : row.action === "update" ? "exists, differs" : "unchanged"}</Badge>;
}

export function ImportDialog({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [step, setStep] = useState<Step>("select");
  const [file, setFile] = useState<File | null>(null);
  const [job, setJob] = useState<ImportJob | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [onExisting, setOnExisting] = useState<"skip" | "update">("skip");
  const [skipInvalid, setSkipInvalid] = useState(false);
  const [mode, setMode] = useState<"atomic" | "per_row">("atomic");
  const [onlyProblems, setOnlyProblems] = useState(true);
  const stop = useRef(false);

  useEffect(() => {
    stop.current = false;
    return () => {
      stop.current = true;
    };
  }, []);

  async function validate() {
    if (!file) return;
    setError(null);
    if (file.size > MAX_BYTES) {
      setError(new Error("The file is larger than 5 MB. Split it into smaller files."));
      return;
    }
    setBusy(true);
    try {
      const content = await file.text();
      const format = file.name.toLowerCase().endsWith(".json") ? "json" : "csv";
      const result = await api.post<ImportJob>("/api/switches/import/validate", { filename: file.name, format, content });
      setJob(result);
      setSkipInvalid(false);
      setStep("preview");
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!job) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/api/switches/import/${job.id}/confirm`, { on_existing: onExisting, skip_invalid: skipInvalid, mode });
      setStep("running");
      for (let i = 0; i < 3600 && !stop.current; i++) {
        const current = await api.get<ImportJob>(`/api/switches/import/${job.id}`, { rows: false });
        setJob((prev) => ({ ...current, rows: prev?.rows }));
        if (current.status !== "queued" && current.status !== "running") break;
        await new Promise((r) => setTimeout(r, 1000));
      }
      setJob(await api.get<ImportJob>(`/api/switches/import/${job.id}`));
      setStep("done");
      onImported();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (!job) return;
    try {
      await api.post(`/api/switches/import/${job.id}/cancel`);
    } catch (err) {
      setError(err);
    }
  }

  const rows = useMemo(() => {
    const all = job?.rows || [];
    return onlyProblems ? all.filter((r) => r.errors.length || r.warnings.length || r.status !== "valid" || r.result === "failed" || r.result === "skipped") : all;
  }, [job, onlyProblems]);
  const problems = (job?.invalid || 0) + (job?.duplicates || 0);
  // Atomic: the file must be fully valid (identical duplicate rows may be skipped).
  const canConfirm =
    !!job && job.status === "validated" && job.valid > 0 && (mode === "atomic" ? job.invalid === 0 && (!job.duplicates || skipInvalid) : problems === 0 || skipInvalid);
  const reportHref = job ? `/api/switches/import/${job.id}/report` : "#";

  const footer =
    step === "select" ? (
      <>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" icon={<FileUp className="h-4 w-4" />} loading={busy} disabled={!file} onClick={validate}>
          Validate file
        </Button>
      </>
    ) : step === "preview" ? (
      <>
        <Button onClick={() => setStep("select")}>Back</Button>
        <Button variant="primary" icon={<Upload className="h-4 w-4" />} loading={busy} disabled={!canConfirm} onClick={confirm}>
          Confirm import of {job?.valid ?? 0} switch{job?.valid === 1 ? "" : "es"}
        </Button>
      </>
    ) : step === "running" ? (
      <Button variant="danger" onClick={cancel} disabled={job?.cancel_requested}>
        {job?.cancel_requested ? "Stopping after this batch…" : "Cancel import"}
      </Button>
    ) : (
      <Button variant="primary" onClick={onClose}>
        Close
      </Button>
    );

  return (
    <Modal open onClose={onClose} width="max-w-4xl" title="Import switches" footer={footer} dismissable={step !== "running"}>
      <div className="space-y-4">
        {step === "select" && (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Upload a CSV or JSON file. Required columns: <span className="mono">name, management_ip</span>; optional:{" "}
              <span className="mono">
                credential_reference, ssh_host_key_fingerprint, ssh_port, hostname, site, location, description, role, environment, enabled, uplink_ports,
                expected_model, expected_aos_version
              </span>
              . Vendor, model and AOS version are <strong>discovered automatically</strong> after the import; a <span className="mono">model</span> /{" "}
              <span className="mono">aos_version</span> column is only compared with what discovery finds. Nothing is changed before you confirm the preview.
            </p>
            <Notice tone="blue" title="Never put passwords in import files">
              Create the SSH account under Settings → Credentials and reference it by name in the <span className="mono">credential_reference</span> column. Files with
              password, key or token columns are rejected. The SSH host-key fingerprint (read on the switch console) lets discovery start without trusting an unverified key.
            </Notice>
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="file"
                accept=".csv,.json,text/csv,application/json"
                aria-label="Import file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="block text-sm file:mr-3 file:rounded-lg file:border-0 file:bg-teal-700 file:px-3 file:py-2 file:text-sm file:font-medium file:text-white hover:file:bg-teal-800"
              />
              <a className="inline-flex items-center gap-1 text-sm text-teal-700 hover:underline dark:text-teal-400" href="/api/switches/import/template?format=csv" download>
                <Download className="h-4 w-4" /> CSV template
              </a>
              <a className="inline-flex items-center gap-1 text-sm text-teal-700 hover:underline dark:text-teal-400" href="/api/switches/import/template?format=json" download>
                <Download className="h-4 w-4" /> JSON template
              </a>
            </div>
          </>
        )}

        {job && step !== "select" && (
          <>
            {job.file_errors.length > 0 ? (
              <Notice tone="red" title="The file was rejected">
                {job.file_errors.join(" ")}
              </Notice>
            ) : (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
                <Stat label="Total" value={job.total} />
                <Stat label="Valid" value={job.valid} tone="green" />
                <Stat label="Invalid" value={job.invalid} tone={job.invalid ? "red" : undefined} />
                <Stat label="Duplicates" value={job.duplicates} tone={job.duplicates ? "amber" : undefined} />
                <Stat label="Warnings" value={job.warnings} tone={job.warnings ? "amber" : undefined} />
                {step === "preview" ? (
                  <>
                    <Stat label="New" value={job.new} />
                    <Stat label="Existing changed" value={job.existing_changed} />
                    <Stat label="Unchanged" value={job.existing_unchanged} />
                  </>
                ) : (
                  <>
                    <Stat label="Imported" value={job.imported + job.updated} tone="green" />
                    <Stat label="Skipped" value={job.skipped + job.unchanged} />
                    <Stat label="Failed" value={job.failed} tone={job.failed ? "red" : undefined} />
                  </>
                )}
              </div>
            )}

            {step === "preview" && job.status === "validated" && (
              <div className="space-y-3 rounded-lg border border-slate-200 p-3 dark:border-slate-800">
                <label className="flex flex-wrap items-center gap-2 text-sm">
                  Switches that already exist with different values:
                  <Select className="w-auto" aria-label="Existing switches" value={onExisting} onChange={(e) => setOnExisting(e.target.value as "skip" | "update")}>
                    <option value="skip">Skip — do not change them</option>
                    <option value="update">Update them with the file's values</option>
                  </Select>
                </label>
                <label className="flex flex-wrap items-center gap-2 text-sm">
                  Mode:
                  <Select className="w-auto" aria-label="Import mode" value={mode} onChange={(e) => setMode(e.target.value as "atomic" | "per_row")}>
                    <option value="atomic">All or nothing (recommended)</option>
                    <option value="per_row">Row by row — skip invalid rows</option>
                  </Select>
                </label>
                {mode === "atomic" && job.invalid > 0 && (
                  <Notice tone="red" title="The file has invalid rows">
                    An all-or-nothing import never imports part of a file. Fix the {job.invalid} invalid row{job.invalid === 1 ? "" : "s"} and upload the file again, or
                    choose row-by-row mode.
                  </Notice>
                )}
                {(mode === "per_row" ? problems > 0 : job.duplicates > 0) && (
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={skipInvalid} onChange={(e) => setSkipInvalid(e.target.checked)} />
                    {mode === "per_row"
                      ? `Skip the ${problems} invalid/duplicate row${problems === 1 ? "" : "s"} and import only the valid ones`
                      : `Skip the ${job.duplicates} identical duplicate row${job.duplicates === 1 ? "" : "s"}`}
                  </label>
                )}
              </div>
            )}

            {(step === "running" || step === "done") && (
              <div>
                <div className="mb-1 flex justify-between text-sm">
                  <span>
                    Status: <b>{job.status}</b>
                  </span>
                  <span className="tabular-nums">
                    {job.processed} / {job.total}
                  </span>
                </div>
                <div className="h-2 overflow-hidden rounded bg-slate-200 dark:bg-slate-800" role="progressbar" aria-valuenow={job.processed} aria-valuemin={0} aria-valuemax={job.total}>
                  <div className="h-full bg-teal-600 transition-all" style={{ width: `${job.total ? (100 * job.processed) / job.total : 0}%` }} />
                </div>
                {job.error && <p className="mt-2 text-sm text-red-700 dark:text-red-400">{job.error}</p>}
                {step === "done" && job.discovery_job_id && (
                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                    Automatic discovery started for the imported switches with a trusted or supplied host-key fingerprint. Follow it on the Switches page.
                  </p>
                )}
              </div>
            )}

            {(job.rows?.length || 0) > 0 && (
              <div>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <label className="flex items-center gap-2 text-sm">
                    <input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} />
                    Show only rows with problems
                  </label>
                  <a className="inline-flex items-center gap-1 text-sm text-teal-700 hover:underline dark:text-teal-400" href={reportHref} download>
                    <Download className="h-4 w-4" /> Download error report
                  </a>
                </div>
                <div className="max-h-80 overflow-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  <Table>
                    <thead>
                      <tr>
                        <Th>Line</Th>
                        <Th>Name</Th>
                        <Th>Management IP</Th>
                        <Th>Status</Th>
                        <Th>Details</Th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.slice(0, 500).map((r) => (
                        <tr key={r.line}>
                          <Td mono>{r.line}</Td>
                          <Td className="font-medium">{r.name}</Td>
                          <Td mono>{r.management_ip}</Td>
                          <Td>
                            <RowStatus row={r} />
                          </Td>
                          <Td className="text-xs">
                            {r.errors.map((e) => (
                              <div key={e} className="text-red-700 dark:text-red-400">
                                {e}
                              </div>
                            ))}
                            {r.warnings.map((w) => (
                              <div key={w} className="text-amber-700 dark:text-amber-400">
                                {w}
                              </div>
                            ))}
                            {r.message && !r.errors.length && <div className="text-slate-500">{r.message}</div>}
                          </Td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                  {rows.length > 500 && <p className="p-2 text-xs text-slate-500">Showing 500 of {rows.length} rows — download the report for all.</p>}
                  {rows.length === 0 && <p className="p-3 text-sm text-slate-500">No problems found.</p>}
                </div>
              </div>
            )}
          </>
        )}
        <ErrorBanner error={error} />
      </div>
    </Modal>
  );
}
