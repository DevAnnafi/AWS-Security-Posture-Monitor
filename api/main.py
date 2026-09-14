from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import (
    Finding as FindingRow,
    FindingState,
    FindingStatus,
    Scan,
)
from api.db.session import SessionLocal
from api.schemas import (
    FindingDetailSchema,
    FindingStateSchema,
    FindingStateUpdateSchema,
    FindingSummarySchema,
    FindingsResponse,
    SummarySchema,
)


app = FastAPI(
    title="AWS Security Posture Monitor"
)


def get_session():
    with SessionLocal() as session:
        yield session


def is_suppression_active(
    state: FindingState | None,
) -> bool:
    return (
        state is not None
        and state.status is FindingStatus.SUPPRESSED
        and state.expires_at is not None
        and state.expires_at > datetime.now(timezone.utc)
    )


def get_effective_status(
    state: FindingState | None,
) -> FindingStatus:
    if is_suppression_active(state):
        return FindingStatus.SUPPRESSED

    if state is None:
        return FindingStatus.NEW

    if state.status is FindingStatus.SUPPRESSED:
        return FindingStatus.NEW

    return state.status


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get(
    "/findings",
    response_model=FindingsResponse,
)
def list_findings(
    scan_id: UUID | None = None,
    severity: str | None = None,
    region: str | None = None,
    control_id: str | None = None,
    include_suppressed: bool = True,
    session: Session = Depends(get_session),
):
    if scan_id is None:
        scan = session.scalars(
            select(Scan)
            .order_by(Scan.scanned_at.desc())
            .limit(1)
        ).first()
    else:
        scan = session.get(Scan, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="No scans found",
        )

    stmt = (
        select(FindingRow, FindingState)
        .outerjoin(
            FindingState,
            FindingRow.finding_id == FindingState.finding_id,
        )
        .where(
            FindingRow.scan_id == scan.scan_id
        )
    )

    if severity is not None:
        stmt = stmt.where(
            FindingRow.severity == severity
        )

    if region is not None:
        stmt = stmt.where(
            FindingRow.region == region
        )

    if control_id is not None:
        stmt = stmt.where(
            FindingRow.control_id == control_id
        )

    rows = session.execute(stmt).all()

    findings: list[FindingSummarySchema] = []

    for finding, state in rows:
        status = get_effective_status(state)

        if (
            not include_suppressed
            and status is FindingStatus.SUPPRESSED
        ):
            continue

        findings.append(
            FindingSummarySchema(
                scan_id=finding.scan_id,
                finding_id=finding.finding_id,
                control_id=finding.control_id,
                title=finding.title,
                severity=finding.severity,
                resource_id=finding.resource_id,
                account_id=finding.account_id,
                remediable=finding.remediable,
                detected_at=finding.detected_at,
                status=status,
                resource_sub_id=finding.resource_sub_id,
                region=finding.region,
            )
        )

    return FindingsResponse(
        scan=scan,
        findings=findings,
    )


@app.get(
    "/findings/{finding_id}",
    response_model=FindingDetailSchema,
)
def get_finding(
    finding_id: str,
    session: Session = Depends(get_session),
):
    stmt = (
        select(FindingRow, FindingState)
        .outerjoin(
            FindingState,
            FindingRow.finding_id == FindingState.finding_id,
        )
        .join(
            Scan,
            FindingRow.scan_id == Scan.scan_id,
        )
        .where(
            FindingRow.finding_id == finding_id
        )
        .order_by(
            Scan.scanned_at.desc()
        )
        .limit(1)
    )

    row = session.execute(stmt).first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    finding, state = row

    return FindingDetailSchema(
        scan_id=finding.scan_id,
        finding_id=finding.finding_id,
        control_id=finding.control_id,
        title=finding.title,
        severity=finding.severity,
        resource_id=finding.resource_id,
        account_id=finding.account_id,
        remediable=finding.remediable,
        detected_at=finding.detected_at,
        status=get_effective_status(state),
        resource_sub_id=finding.resource_sub_id,
        region=finding.region,
        evidence=finding.evidence,
    )


@app.get(
    "/summary",
    response_model=SummarySchema,
)
def get_summary(
    session: Session = Depends(get_session),
):
    latest_scan = session.scalars(
        select(Scan)
        .order_by(Scan.scanned_at.desc())
        .limit(1)
    ).first()

    if latest_scan is None:
        raise HTTPException(
            status_code=404,
            detail="No scans found",
        )

    stmt = (
        select(FindingRow, FindingState)
        .outerjoin(
            FindingState,
            FindingRow.finding_id == FindingState.finding_id,
        )
        .where(
            FindingRow.scan_id == latest_scan.scan_id
        )
    )

    rows = session.execute(stmt).all()

    by_severity: dict[str, int] = {}
    by_control: dict[str, int] = {}
    suppressed_count = 0

    for finding, state in rows:
        status = get_effective_status(state)

        if status is FindingStatus.SUPPRESSED:
            suppressed_count += 1
            continue

        by_severity[finding.severity] = (
            by_severity.get(finding.severity, 0) + 1
        )

        by_control[finding.control_id] = (
            by_control.get(finding.control_id, 0) + 1
        )

    return SummarySchema(
        scan_id=latest_scan.scan_id,
        scanned_at=latest_scan.scanned_at,
        by_severity=by_severity,
        by_control=by_control,
        suppressed_count=suppressed_count,
    )


@app.patch(
    "/findings/{finding_id}/state",
    response_model=FindingStateSchema,
)
def update_finding_state(
    finding_id: str,
    update: FindingStateUpdateSchema,
    session: Session = Depends(get_session),
):
    finding = session.scalars(
        select(FindingRow)
        .where(
            FindingRow.finding_id == finding_id
        )
        .limit(1)
    ).first()

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    provided = update.model_dump(
        exclude_unset=True
    )

    state = session.get(
        FindingState,
        finding_id,
    )

    if state is None:
        state = FindingState(
            finding_id=finding_id,
            status=FindingStatus.NEW,
        )
        session.add(state)

    for field, value in provided.items():
        setattr(state, field, value)

    session.commit()
    session.refresh(state)

    return state