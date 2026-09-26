import { Network, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { Button, ErrorBanner, Field, Input } from "../components/ui";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError(err);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-gradient-to-br from-slate-100 via-slate-50 to-teal-50 p-4 dark:from-slate-950 dark:via-slate-950 dark:to-teal-950/40">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-teal-700 text-white shadow">
            <Network className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Network Operations</h1>
            <p className="text-xs text-slate-500">Alcatel-Lucent Enterprise · AOS network operations</p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <Field label="Username">
            <Input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </Field>
          <Field label="Password">
            <Input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </Field>
          <ErrorBanner error={error} />
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Sign in
          </Button>
        </form>
        <p className="mt-4 flex items-center justify-center gap-1.5 text-xs text-slate-500">
          <ShieldCheck className="h-3.5 w-3.5" /> All actions are audited.
        </p>
      </div>
    </div>
  );
}
