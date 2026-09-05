from enum import Enum
from dataclasses import dataclass, field
from scanner.models import Finding
from abc import ABC, abstractmethod

class CheckStatus(Enum):
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
    remediable: bool
    requires: list[str]

    @abstractmethod
    def evaluate(self, snapshot) -> CheckResult:
        raise NotImplementedError

    def __init_subclass__(cls, **kwargs):
      super().__init_subclass__(**kwargs)
      CHECK_REGISTRY[cls.control_id] = cls

