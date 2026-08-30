from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any
from datetime import datetime, timezone
import hashlib


class Severity(IntEnum):
    # four members
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class Finding:
    control_id: str
    title: str
    severity: Severity
    resource_id: str
    resource_sub_id: str | None
    region: str | None
    remediable: bool
    evidence: dict[str, Any]
    account_id: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finding_id: str = field(init=False)

    def __post_init__(self):
        joined = "|".join([self.account_id, self.region or "", self.control_id, self.resource_id, self.resource_sub_id or ""])
        encode = joined.encode()
        self.finding_id = hashlib.sha256(encode).hexdigest()

    def to_dict(self):
        finding_dict = asdict(self)
        finding_dict["detected_at"] = self.detected_at.isoformat()
        finding_dict["severity"] = self.severity.name
        return finding_dict

    @classmethod
    def from_dict(cls, finding_dict):
        finding_dict["detected_at"] = datetime.fromisoformat(finding_dict["detected_at"])
        finding_dict["severity"] = Severity[finding_dict["severity"]]

        finding_dict.pop("finding_id")

        return cls(**finding_dict)













