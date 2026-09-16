import Link from "next/link";
import { ScanHeader } from "./components/ScanHeader";
import {
  getFindings,
  getSummary,
  NoScansError,
  type FindingSummary,
  type Severity,
} from "@/lib/api";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function EmptyState({ message }: { message: string }) {
  return (
    <div className="border border-rule px-6 py-10 text-center">
      <p className="text-ink-soft">{message}</p>
      <p className="mt-2 font-mono text-sm text-ink-faint">
        python -m scanner
      </p>
    </div>
  );
}

function FindingRow({ finding }: { finding: FindingSummary }) {
  const suppressed = finding.status === "suppressed";

  return (
    <li className={suppressed ? "opacity-55" : undefined}>
      <Link
        href={`/findings/${finding.finding_id}`}
        className={`sev-rule sev-${finding.severity} block py-3 pl-4 hover:bg-paper-sunk`}
      >
        <div className="flex items-baseline justify-between gap-4">
          <span className="font-medium">{finding.title}</span>
          <span className="shrink-0 text-sm text-ink-faint">
            {finding.severity.toLowerCase()}
            {suppressed && " · suppressed"}
          </span>
        </div>

        <p className="mt-1 truncate font-mono text-[0.8125rem] text-ink-soft">
          {finding.resource_id}
          {finding.resource_sub_id && ` · ${finding.resource_sub_id}`}
        </p>

        <p className="mt-1 text-sm text-ink-faint">
          CIS {finding.control_id} · {finding.region ?? "global"}
        </p>
      </Link>
    </li>
  );
}

export default async function FindingsPage() {
  let data;
  let summary;

  try {
    [data, summary] = await Promise.all([getFindings(), getSummary()]);
  } catch (error) {
    if (error instanceof NoScansError) {
      return (
        <EmptyState message="No scans recorded yet. Run one to see findings here." />
      );
    }
    throw error;
  }

  const open = data.findings.filter((f) => f.status !== "suppressed");

  const counts = severityOrder
    .map((severity) => ({
      severity,
      count: summary.by_severity[severity] ?? 0,
    }))
    .filter((entry) => entry.count > 0);

  return (
    <>
      <ScanHeader scan={data.scan} />

      <div className="mb-8 flex flex-wrap items-baseline gap-x-8 gap-y-3 border-y border-rule py-4">
        <p className="text-2xl font-semibold tabular-nums">
          {open.length}
          <span className="ml-2 text-sm font-normal text-ink-soft">
            {open.length === 1 ? "open finding" : "open findings"}
          </span>
        </p>

        {counts.map(({ severity, count }) => (
          <p key={severity} className="flex items-center gap-2 text-sm">
            <span className={`sev-dot sev-dot-${severity}`} aria-hidden />
            <span className="tabular-nums">{count}</span>
            <span className="text-ink-soft">{severity.toLowerCase()}</span>
          </p>
        ))}

        {summary.suppressed_count > 0 && (
          <p className="text-sm text-ink-soft">
            <span className="tabular-nums">{summary.suppressed_count}</span>{" "}
            suppressed, not counted above
          </p>
        )}
      </div>

      {data.findings.length === 0 ? (
        <EmptyState message="This scan found nothing to report." />
      ) : (
        <ul className="divide-y divide-rule border-y border-rule">
          {data.findings.map((finding) => (
            <FindingRow key={finding.finding_id} finding={finding} />
          ))}
        </ul>
      )}
    </>
  );
}