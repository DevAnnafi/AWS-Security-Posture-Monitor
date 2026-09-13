from api.db.models import Scan
from api.db.models import Finding as FindingRow
from api.db.models import UnEvalTarget 
from api.db.models import FindingState
from api.db.models import FindingStatus

def write_scan_results(session, scan_results):
    scan = Scan(
        scan_id=scan_results.scan_id,
        account_id=scan_results.account_id,
        status=scan_results.status,
        regions_covered=scan_results.regions_covered,
        scanned_at=scan_results.scanned_at,
        ended_at=scan_results.ended_at
    )
    session.add(scan)
    session.flush()

    for check_result in scan_results.results:
        for finding in check_result.findings:
            row = FindingRow(
                scan_id=scan_results.scan_id,
                control_id=finding.control_id,
                title=finding.title,
                severity=finding.severity.name,
                resource_id=finding.resource_id,
                resource_sub_id=finding.resource_sub_id,
                region=finding.region,
                remediable=finding.remediable,
                evidence=finding.evidence,
                account_id=finding.account_id,
                detected_at=finding.detected_at,
                finding_id=finding.finding_id
            )
            session.add(row)

            existing = session.get(FindingState, finding.finding_id)
            if existing is None:
                session.add(FindingState(
                    finding_id=finding.finding_id,
                    status=FindingStatus.NEW,
                ))

        for entry in check_result.unevaluated:
            target_row = UnEvalTarget(
                scan_id=scan_results.scan_id,
                control_id=check_result.control_id,
                target_type=entry["target_type"],
                target=entry["target"],
                value=entry["value"],
                reason=entry["reason"],
            )
            session.add(target_row)

    