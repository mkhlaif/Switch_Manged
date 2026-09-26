import { SafetyTab } from "../components/SafetyTab";
import { PageHeader } from "../components/ui";

export default function SafetyPage() {
  return (
    <>
      <PageHeader
        title="Safety Controls"
        subtitle="Operation mode, kill switch, circuit breaker, locks and the authoritative operation policy. Every change is audited."
      />
      <SafetyTab />
    </>
  );
}
