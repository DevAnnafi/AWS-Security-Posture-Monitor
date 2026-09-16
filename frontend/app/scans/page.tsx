import { formatTimestamp, getScans, NoScansError, type Scan } from "@/lib/api";

function ScanRow({ scan, latest }: { scan: Scan; latest: boolean }) {
  const complete = scan.status === "COMPLETED";

  return (
    <li
      className={`border-l-[3px] py-3 pl-4 ${
        complete ? "border-rule" : "border-unknown"
      }`}
    >
      <div className="flex items-baseline justify-between gap-4">
        <span className="font-mono text-[0.875rem]">
          {scan.scan_id.slice(0, 8)}
        </span>
        <span className="text-sm text-ink-faint">
          {latest && "most recent · "}
          {scan.status.toLowerCase()}
        </span>
      </div>

      <p className="mt-1 text-sm text-ink-soft">
        {formatTimestamp(scan.scanned_at)}
      </p>

      <p className="mt-1 font-mono text-[0.8125rem] text-ink-faint">
        {scan.regions_covered.join("  ")}
      </p>
    </li>
  );
}

export default async function ScanHistoryPage() {
  let scans: Scan[];

  try {
    scans = await getScans();
  } catch (error) {
    if (error instanceof NoScansError) {
      return (
        <div className="border border-rule px-6 py-10 text-center">
          <p className="text-ink-soft">No scans recorded yet.</p>
        </div>
      );
    }
    throw error;
  }

  const incomplete = scans.filter((s) => s.status !== "COMPLETED").length;

  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight">Scan history</h1>

      <p className="mt-3 max-w-prose text-sm text-ink-soft">
        Every scan is recorded, including ones that found nothing. A scan with
        no findings and a scan that could not run look the same in a report
        that only lists problems, so both are kept here.
      </p>

      <div className="my-8 flex gap-8 border-y border-rule py-4 text-sm">
        <p>
          <span className="text-lg font-semibold tabular-nums">
            {scans.length}
          </span>
          <span className="ml-2 text-ink-soft">
            {scans.length === 1 ? "scan" : "scans"}
          </span>
        </p>
        {incomplete > 0 && (
          <p>
            <span className="text-lg font-semibold tabular-nums">
              {incomplete}
            </span>
            <span className="ml-2 text-ink-soft">incomplete</span>
          </p>
        )}
      </div>

      <ul className="divide-y divide-rule border-y border-rule">
        {scans.map((scan, index) => (
          <ScanRow key={scan.scan_id} scan={scan} latest={index === 0} />
        ))}
      </ul>
    </>
  );
}