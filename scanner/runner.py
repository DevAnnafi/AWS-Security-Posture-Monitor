from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from scanner.registry import CheckResult, CHECK_REGISTRY

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
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = field(default=None)

def run_scan(snapshot):
    for check_class in CHECK_REGISTRY.values():
        print(check_class)


    