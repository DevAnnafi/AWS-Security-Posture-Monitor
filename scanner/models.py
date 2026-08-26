"""Core data structures.

TODO: define Finding (cis_control, title, severity, resource_arn, region,
      remediable, evidence) and Severity. Every check returns a list of these.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Any
from datetime import datetime

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
    detected_at: datetime
    finding_id: str
    account_id: str





