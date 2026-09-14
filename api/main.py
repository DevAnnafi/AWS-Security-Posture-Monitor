from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from api.db.session import SessionLocal
from api.db.models import (
    Scan,
    Finding as FindingRow,
    FindingState,
    FindingStatus,
)
from api.schemas import (
    FindingsResponse,
    FindingDetailSchema,
    FindingStateSchema,
    FindingStateUpdateSchema,
    SummarySchema,
)


app = FastAPI(
    title="AWS Security Posture Monitor"
)


def get_session():
    with SessionLocal() as session:
        yield session


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/findings", response_model=FindingsResponse)
def list_findings(
    scan_id: UUID | None = None,
    severity: str | None = None,
    region: str | None = None,
    control_id: str | None = None,
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

    stmt = select(FindingRow).where(
        FindingRow.scan_id == scan.scan_id
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

    findings = list(session.scalars(stmt))

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
        select(FindingRow)
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

    finding = session.scalars(stmt).first()

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding


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

    severity_rows = session.execute(
        select(
            FindingRow.severity,
            func.count(FindingRow.finding_id),
        )
        .where(
            FindingRow.scan_id == latest_scan.scan_id
        )
        .group_by(
            FindingRow.severity
        )
    ).all()

    control_rows = session.execute(
        select(
            FindingRow.control_id,
            func.count(FindingRow.finding_id),
        )
        .where(
            FindingRow.scan_id == latest_scan.scan_id
        )
        .group_by(
            FindingRow.control_id
        )
    ).all()

    return SummarySchema(
        scan_id=latest_scan.scan_id,
        scanned_at=latest_scan.scanned_at,
        by_severity={
            severity: count
            for severity, count in severity_rows
        },
        by_control={
            control_id: count
            for control_id, count in control_rows
        },
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

    provided = update.model_dump(exclude_unset=True)

    current_state = session.get(
        FindingState,
        finding_id,
    )

    current_status = (
        provided.get("status")
        if "status" in provided
        else (
            current_state.status
            if current_state is not None
            else FindingStatus.NEW
        )
    )

    if current_status == FindingStatus.SUPPRESSED:
        suppressed_by = (
            provided.get("suppressed_by")
            if "suppressed_by" in provided
            else (
                current_state.suppressed_by
                if current_state is not None
                else None
            )
        )

        justification = (
            provided.get("justification")
            if "justification" in provided
            else (
                current_state.justification
                if current_state is not None
                else None
            )
        )

        expires_at = (
            provided.get("expires_at")
            if "expires_at" in provided
            else (
                current_state.expires_at
                if current_state is not None
                else None
            )
        )

        if not suppressed_by:
            raise HTTPException(
                status_code=400,
                detail="Suppression requires suppressed_by",
            )

        if not justification:
            raise HTTPException(
                status_code=400,
                detail="Suppression requires a justification",
            )

        if expires_at is None:
            raise HTTPException(
                status_code=400,
                detail="Suppression requires an expiry",
            )

    if current_state is None:
        current_state = FindingState(
            finding_id=finding_id,
            status=current_status,
        )
        session.add(current_state)

    for field, value in provided.items():
        setattr(current_state, field, value)

    session.commit()
    session.refresh(current_state)

    return current_state