import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Credential, Profile, Switch, SwitchRole } from "../api/types";
import { Button, ErrorBanner, Field, Input, Modal, Select, Textarea, Toggle } from "./ui";

interface FormState {
  name: string;
  host: string;
  hostname: string;
  ssh_port: number;
  expected_model: string;
  expected_aos_version: string;
  expected_host_key_fingerprint: string;
  environment: "production" | "lab";
  site: string;
  location: string;
  port_locations: string;
  description: string;
  enabled: boolean;
  credential_id: number | null;
  profile_key: string;
  transport: "ssh" | "simulator";
  legacy_ssh_algorithms: boolean;
  uplink_ports: string;
  role: SwitchRole;
}

function toForm(s?: Switch): FormState {
  return {
    name: s?.name || "",
    host: s?.host || "",
    hostname: s?.hostname || "",
    ssh_port: s?.ssh_port || 22,
    expected_model: s?.expected_model || "",
    expected_aos_version: s?.expected_aos_version || "",
    expected_host_key_fingerprint: s?.expected_host_key_fingerprint || "",
    environment: s?.environment || "production",
    site: s?.site || "",
    location: s?.location || "",
    port_locations: Object.entries(s?.port_locations || {})
      .map(([port, label]) => `${port} = ${label}`)
      .join("\n"),
    description: s?.description || "",
    enabled: s?.enabled ?? true,
    credential_id: s?.credential_id ?? null,
    profile_key: s?.profile_key || "",
    transport: s?.transport || "ssh",
    legacy_ssh_algorithms: s?.legacy_ssh_algorithms || false,
    uplink_ports: (s?.uplink_ports || []).join(", "),
    role: s?.role || "unknown",
  };
}

export function SwitchForm({ existing, labMode, onClose, onSaved }: { existing?: Switch; labMode: boolean; onClose: () => void; onSaved: (s: Switch) => void }) {
  const [form, setForm] = useState<FormState>(toForm(existing));
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<Credential[]>("/api/credentials").then(setCredentials).catch(setError);
    api.get<{ profiles: Profile[] }>("/api/profiles").then((r) => setProfiles(r.profiles)).catch(() => undefined);
  }, []);

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm((f) => ({ ...f, [k]: v }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const portLocations: Record<string, string> = {};
    for (const line of form.port_locations.split("\n")) {
      if (!line.trim()) continue;
      const at = line.indexOf("=");
      if (at < 1) {
        setError(new Error(`Port location "${line.trim()}" must look like "1/1/5 = Building A - Office 204".`));
        setBusy(false);
        return;
      }
      portLocations[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
    const body = {
      ...form,
      port_locations: portLocations,
      uplink_ports: form.uplink_ports
        .split(/[\s,]+/)
        .map((p) => p.trim())
        .filter(Boolean),
    };
    try {
      const saved = existing ? await api.patch<Switch>(`/api/switches/${existing.id}`, body) : await api.post<Switch>("/api/switches", body);
      onSaved(saved);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      width="max-w-3xl"
      title={existing ? `Edit ${existing.name}` : "Add switch"}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={busy} onClick={submit}>
            Save
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Name">
          <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="SW-ACCESS-01" required />
        </Field>
        <Field label="Management IP / hostname">
          <Input value={form.host} onChange={(e) => set("host", e.target.value)} placeholder="192.0.2.10" className="mono" required />
        </Field>
        <Field label="Hostname" hint="DNS name of the switch (optional, unique).">
          <Input value={form.hostname} onChange={(e) => set("hostname", e.target.value)} placeholder="sw01.example.net" className="mono" />
        </Field>
        <Field label="SSH port">
          <Input type="number" min={1} max={65535} value={form.ssh_port} onChange={(e) => set("ssh_port", Number(e.target.value))} />
        </Field>
        <Field label="Credential" hint="Passwords are stored encrypted and never shown.">
          <Select value={form.credential_id ?? ""} onChange={(e) => set("credential_id", e.target.value ? Number(e.target.value) : null)}>
            <option value="">— select —</option>
            {credentials.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.username})
              </option>
            ))}
          </Select>
        </Field>
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600 sm:col-span-2 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
          Vendor, model and AOS version are <strong>discovered automatically</strong> from the switch (read-only{" "}
          <span className="mono">show system</span>). You never type them. Optional expected values below are only compared with what
          discovery finds: a difference blocks every state-changing operation until an administrator reviews it.
          {existing && existing.discovery_status === "discovered" && (
            <div className="mt-1 text-xs">
              Discovered: <span className="mono">{existing.model}</span> · AOS <span className="mono">{existing.aos_version}</span>
            </div>
          )}
        </div>
        <Field label="Expected model (optional)" hint="Compared with the discovered model family, e.g. OS6450-P24.">
          <Input value={form.expected_model} onChange={(e) => set("expected_model", e.target.value)} placeholder="OS6450-P24" />
        </Field>
        <Field label="Expected AOS version (optional)" hint="Compared on major.minor, e.g. 8.10R1 or 6.7.1.">
          <Input value={form.expected_aos_version} onChange={(e) => set("expected_aos_version", e.target.value)} className="mono" />
        </Field>
        <Field
          label="Expected SSH host-key fingerprint (optional)"
          hint="SHA256:… read on the switch console. When it matches, the key is trusted and discovery runs automatically."
        >
          <Input
            value={form.expected_host_key_fingerprint}
            onChange={(e) => set("expected_host_key_fingerprint", e.target.value)}
            placeholder="SHA256:…"
            className="mono"
          />
        </Field>
        <Field label="Environment" hint="Production switches need PRODUCTION_VERIFIED command profiles for any state change.">
          <Select value={form.environment} onChange={(e) => set("environment", e.target.value as "production" | "lab")}>
            <option value="production">Production</option>
            <option value="lab">Lab</option>
          </Select>
        </Field>
        <Field label="Site">
          <Input value={form.site} onChange={(e) => set("site", e.target.value)} placeholder="Main campus" />
        </Field>
        <Field label="Location">
          <Input value={form.location} onChange={(e) => set("location", e.target.value)} placeholder="Building A / Floor 2" />
        </Field>
        <Field label="Command profile" hint="Automatic selects the verified profile from the discovered model and AOS version.">
          <Select value={form.profile_key} onChange={(e) => set("profile_key", e.target.value)}>
            <option value="">Automatic</option>
            {profiles.map((p) => (
              <option key={p.key} value={p.key} disabled={!p.enabled}>
                {p.key} — {p.name}
                {!p.enabled ? " (disabled)" : ""}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Topology role" hint="Core and distribution switch ports are infrastructure: restarts are blocked outside EMERGENCY mode.">
          <Select value={form.role} onChange={(e) => set("role", e.target.value as SwitchRole)}>
            <option value="unknown">Unknown</option>
            <option value="access">Access</option>
            <option value="distribution">Distribution</option>
            <option value="core">Core</option>
          </Select>
        </Field>
        <div className="sm:col-span-2">
          <Field label="Uplink / trunk ports" hint="Comma-separated (e.g. 1/1/49, 1/1/50 or 1/25). These are always classified UPLINK and can never be restarted.">
            <Input value={form.uplink_ports} onChange={(e) => set("uplink_ports", e.target.value)} className="mono" />
          </Field>
        </div>
        <div className="sm:col-span-2">
          <Field
            label="Device locations per port"
            hint='One per line: "1/1/5 = Building A - Floor 2 - Office 204". This is the only location MAC operators see; without it they see site and location.'
          >
            <Textarea rows={3} value={form.port_locations} onChange={(e) => set("port_locations", e.target.value)} className="mono" />
          </Field>
        </div>
        <div className="sm:col-span-2">
          <Field label="Description">
            <Textarea rows={2} value={form.description} onChange={(e) => set("description", e.target.value)} />
          </Field>
        </div>
        <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-800">
          <div>
            <div className="text-sm font-medium">Enabled</div>
            <div className="text-xs text-slate-500">Included in MAC searches</div>
          </div>
          <Toggle checked={form.enabled} onChange={(v) => set("enabled", v)} label="Enabled" />
        </div>
        <div className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-800">
          <div>
            <div className="text-sm font-medium">Legacy SSH algorithms</div>
            <div className="text-xs text-slate-500">Only for old AOS 6 releases (SHA-1 KEX, CBC)</div>
          </div>
          <Toggle checked={form.legacy_ssh_algorithms} onChange={(v) => set("legacy_ssh_algorithms", v)} label="Legacy algorithms" />
        </div>
        {labMode && (
          <Field label="Transport" hint="Lab mode only.">
            <Select value={form.transport} onChange={(e) => set("transport", e.target.value as "ssh" | "simulator")}>
              <option value="ssh">SSH</option>
              <option value="simulator">Simulator</option>
            </Select>
          </Field>
        )}
        <div className="sm:col-span-2">
          <ErrorBanner error={error} />
        </div>
        <button type="submit" className="hidden" />
      </form>
    </Modal>
  );
}
