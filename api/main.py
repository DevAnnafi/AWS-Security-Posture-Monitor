from fastapi import FastAPI, Depends, HTTPException
from api.db.session import SessionLocal
from sqlalchemy import select
from sqlalchemy.orm import Session
from uuid import UUID
from api.db.models import Scan
from api.schemas import FindingsResponse
from api.db.models import Finding as FindingRow

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
            select(Scan).order_by(Scan.scanned_at.desc()).limit(1)
        ).first()
    else:
        scan = session.get(Scan, scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="No scans found")

    stmt = select(FindingRow).where(FindingRow.scan_id == scan.scan_id)

    if severity is not None:
        stmt = stmt.where(FindingRow.severity == severity)

    if region is not None:
        stmt = stmt.where(FindingRow.region == region)

    if control_id is not None:
        stmt = stmt.where(FindingRow.control_id == control_id)

    findings = list(session.scalars(stmt))

    return FindingsResponse(scan=scan, findings=findings)





