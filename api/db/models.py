from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass

class Finding(Base):
    __tablename__ = "finding"

    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
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

    status: Mapped[str] = mapped_column(
        String,
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