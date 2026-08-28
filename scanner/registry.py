"""Check discovery and registration.

TODO: decide how checks announce themselves - decorator-based registry vs.
      module scanning. This decision determines how cheap check #7 through
      #40 are to add, and how shared API calls get cached across checks.
"""

from enum import Enum
from dataclasses import dataclass
from scanner.models import Finding

class CheckStatus(Enum):
    # Three members
    VIOLATIONS = "violations"
    EVALUATED = "evaluated"
    CANT_EVALUATE = "not_evaluated"

@dataclass
class CheckResult:
    status: CheckStatus
    findings: list[Finding]
    control_id: str
    error: str | None

