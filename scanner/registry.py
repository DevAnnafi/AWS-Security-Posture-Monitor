"""Check discovery and registration.

TODO: decide how checks announce themselves - decorator-based registry vs.
      module scanning. This decision determines how cheap check #7 through
      #40 are to add, and how shared API calls get cached across checks.
"""

from enum import Enum
from dataclasses import dataclass, field
from scanner.models import Finding, Severity
from abc import ABC, abstractmethod

class CheckStatus(Enum):
    # Three members
    VIOLATIONS = "violations"
    EVALUATED = "evaluated"
    CANT_EVALUATE = "not_evaluated"
    PARTIAL="partial"

@dataclass
class CheckResult:
    status: CheckStatus
    findings: list[Finding]
    control_id: str
    error: str | None
    unevaluated: list[dict[str, str]] = field(default_factory=list)

CHECK_REGISTRY: dict[str, type[BaseCheck]] = {}

class BaseCheck(ABC):
    control_id: str
    title: str
    severity: Severity
    remediable: bool
    requires: list[str]

    @abstractmethod
    def evaluate(self, snapshot) -> CheckResult:
        raise NotImplementedError

    def __init_subclass__(cls, **kwargs):
      super().__init_subclass__(**kwargs)
      CHECK_REGISTRY[cls.control_id] = cls

