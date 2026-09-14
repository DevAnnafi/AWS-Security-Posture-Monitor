from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, Field

from api.db.models import FindingStatus
from scanner.runner import ScanStatus


class BaseSchema(BaseModel):
    model_config = {
        "from_attributes": True,
        "use_enum_values": True, 
    }

class FindingSummarySchema(BaseSchema):
    scan_id: UUID
    finding_id: str
    control_id: str
    title: str
    severity: str
    resource_id: str
    account_id: str
    remediable: bool
    detected_at: datetime
    resource_sub_id: str | None = None
    region: str | None = None


class FindingDetailSchema(FindingSummarySchema):
    evidence: Any


class FindingStateSchema(BaseSchema):
    finding_id: str
    status: FindingStatus
    suppressed_by: str | None = None
    justification: str | None = None
    expires_at: datetime | None = None


class ScanSchema(BaseSchema):
    scan_id: UUID
    account_id: str
    status: ScanStatus
    regions_covered: list[str] = Field(default_factory=list)
    scanned_at: datetime
    ended_at: datetime | None = None

class FindingsResponse(BaseSchema):
    scan: ScanSchema
    findings: list[FindingSummarySchema]
