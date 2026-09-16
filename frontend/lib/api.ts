const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type FindingStatus =
  | "new"
  | "acknowledged"
  | "remediated"
  | "suppressed";
export type ScanStatus = "COMPLETED" | "INCOMPLETE" | "FAILED";

export interface Scan {
  scan_id: string;
  account_id: string;
  status: ScanStatus;
  regions_covered: string[];
  scanned_at: string;
  ended_at: string | null;
}

export interface FindingSummary {
  scan_id: string;
  finding_id: string;
  control_id: string;
  title: string;
  severity: Severity;
  resource_id: string;
  account_id: string;
  remediable: boolean;
  detected_at: string;
  status: FindingStatus;
  resource_sub_id: string | null;
  region: string | null;
}

export interface FindingDetail extends FindingSummary {
  evidence: unknown;
}

export interface FindingsResponse {
  scan: Scan;
  findings: FindingSummary[];
}

export interface Summary {
  scan_id: string;
  scanned_at: string;
  by_severity: Record<string, number>;
  by_control: Record<string, number>;
  suppressed_count: number;
}

export interface FindingState {
  finding_id: string;
  status: FindingStatus;
  suppressed_by: string | null;
  justification: string | null;
  expires_at: string | null;
}

/** Thrown when the API responds but the scanner has no data yet. */
export class NoScansError extends Error {}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: "no-store" });

  if (response.status === 404) {
    throw new NoScansError(path);
  }

  if (!response.ok) {
    throw new Error(`${path} responded ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export function getFindings(params?: {
  severity?: string;
  region?: string;
  controlId?: string;
  includeSuppressed?: boolean;
}): Promise<FindingsResponse> {
  const query = new URLSearchParams();

  if (params?.severity) query.set("severity", params.severity);
  if (params?.region) query.set("region", params.region);
  if (params?.controlId) query.set("control_id", params.controlId);
  if (params?.includeSuppressed === false) {
    query.set("include_suppressed", "false");
  }

  const suffix = query.toString() ? `?${query}` : "";
  return get<FindingsResponse>(`/findings${suffix}`);
}

export function getFinding(findingId: string): Promise<FindingDetail> {
  return get<FindingDetail>(`/findings/${findingId}`);
}

export function getSummary(): Promise<Summary> {
  return get<Summary>("/summary");
}

/**
 * Requires a GET /scans endpoint on the API, which does not exist yet.
 * See the note in the dashboard README.
 */
export function getScans(): Promise<Scan[]> {
  return get<Scan[]>("/scans");
}

export async function updateFindingState(
  findingId: string,
  body: {
    status: FindingStatus;
    suppressed_by?: string;
    justification?: string;
    expires_at?: string;
  },
): Promise<FindingState> {
  const response = await fetch(
    `${API_URL}/findings/${findingId}/state`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );

  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(
      detail?.detail?.[0]?.msg ??
        detail?.detail ??
        `Update failed (${response.status})`,
    );
  }

  return response.json() as Promise<FindingState>;
}

export function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}