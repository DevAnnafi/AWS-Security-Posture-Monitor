from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from scanner.registry import CheckResult, CHECK_REGISTRY, CheckStatus
import scanner.checks


class ScanStatus(str, Enum):
    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


@dataclass
class ScanResults:
    account_id: str
    regions_covered: list[str]
    status: ScanStatus
    results: list[CheckResult]
    scanned_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    ended_at: datetime | None = field(default=None)


def run_scan(snapshot):
    scanned_at = datetime.now(timezone.utc)
    results = []

    for check_class in CHECK_REGISTRY.values():
        has_required_sections = all(
            section in snapshot
            for section in check_class.requires
        )

        if has_required_sections:
            check = check_class()
            result = check.evaluate(snapshot)
        else:
            result = CheckResult(
                status=CheckStatus.CANT_EVALUATE,
                findings=[],
                control_id=check_class.control_id,
                error="SECTION_NOT_COLLECTED",
            )

        results.append(result)

    ended_at = datetime.now(timezone.utc)

    return ScanResults(
        account_id=snapshot["account_id"],
        regions_covered=snapshot["regions_covered"],
        status=determine_scan_status(results),
        results=results,
        scanned_at=scanned_at,
        ended_at=ended_at,
    )


def determine_scan_status(results):
    if not results:
        return ScanStatus.FAILED

    if any(
        result.status not in {
            CheckStatus.EVALUATED,
            CheckStatus.VIOLATIONS,
        }
        for result in results
    ):
        return ScanStatus.INCOMPLETE

    return ScanStatus.COMPLETED