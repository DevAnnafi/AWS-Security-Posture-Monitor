import { formatTimestamp, type Scan } from "@/lib/api";

const scanStatusCopy: Record<Scan["status"], string> = {
  COMPLETED: "Every check ran and every resource was readable.",
  INCOMPLETE: "Some checks could not run or could not read every resource.",
  FAILED: "The scan did not produce a usable result.",
};

export function ScanHeader({ scan }: { scan: Scan }) {
  const complete = scan.status === "COMPLETED";

  return (
    <section className="mb-8">
      <h1 className="text-2xl font-semibold tracking-tight">
        Account {scan.account_id}
      </h1>

      <p
        className={`mt-3 border-l-[3px] py-1 pl-3 text-sm ${
          complete
            ? "border-rule text-ink-soft"
            : "border-unknown bg-unknown-wash text-ink"
        }`}
      >
        {scanStatusCopy[scan.status]}
      </p>

      <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-sm">
        <div>
          <dt className="text-ink-faint">Scanned</dt>
          <dd>{formatTimestamp(scan.scanned_at)}</dd>
        </div>
        <div>
          <dt className="text-ink-faint">Regions</dt>
          <dd className="font-mono text-[0.8125rem]">
            {scan.regions_covered.join("  ")}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Scan</dt>
          <dd className="font-mono text-[0.8125rem]">
            {scan.scan_id.slice(0, 8)}
          </dd>
        </div>
      </dl>
    </section>
  );
}