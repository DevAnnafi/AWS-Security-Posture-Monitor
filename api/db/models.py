from datetime import datetime
from typing import Any
from uuid import UUID
from enum import Enum

from sqlalchemy import Enum as SQLEnum
from sqlalchemy import Boolean, DateTime, String, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from scanner.runner import ScanStatus
from scanner.collector import CollectionStatus


class Base(DeclarativeBase):
    pass

class FindingStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"

class TargetType(str, Enum):
    BUCKET = "bucket"
    REGION = "region"
    POLICY = "policy"

class Finding(Base):
    __tablename__ = "findings"

    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.scan_id"),
        primary_key=True,
    )

    finding_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    control_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    resource_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    resource_sub_id: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    region: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    account_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    remediable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

class FindingState(Base):
    __tablename__ = "finding_state"

    finding_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    status: Mapped[FindingStatus] = mapped_column(
        SQLEnum(FindingStatus),
        nullable=False,
    )

    suppressed_by: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    justification: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
    )

    account_id: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus),
        nullable=False
    )

    regions_covered: Mapped[list[str]] = mapped_column(
        JSONB, 
        nullable=False, 
        default=list
    )

    scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

class UnEvalTarget(Base):
    __tablename__ = "uneval_targets"

    id: Mapped[int] = mapped_column(
        Integer, 
        primary_key=True, 
        autoincrement=True
    )

    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.scan_id"),
        nullable=False,     
    )

    control_id: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    target_type: Mapped[str] = mapped_column(
        String, nullable=False
    )

    target: Mapped[str] = mapped_column(
        String,
        nullable=False
    )

    value: Mapped[str | None] = mapped_column(
        String,
        nullable=True
    )

    reason: Mapped[CollectionStatus] = mapped_column(
        SQLEnum(CollectionStatus, values_callable=lambda e: [m.value for m in e]),
        nullable=False
    )

