from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from api.db.models import Finding as FindingRow
from api.db.models import FindingState, FindingStatus, Scan
from api.db.session import engine
from api.db.writer import write_scan_results
from scanner.fixtures import FIXTURE
from scanner.runner import run_scan

from sqlalchemy.orm import Session


@pytest.fixture
def session():
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def test_writer_persists_scan_and_findings(session):
    result = run_scan(FIXTURE)

    write_scan_results(session, result)
    session.commit()

    scans = list(session.scalars(select(Scan)))
    assert len(scans) == 1
    assert scans[0].scan_id == result.scan_id

    findings = list(session.scalars(select(FindingRow)))
    assert len(findings) == 1
    assert findings[0].control_id == "3.1.4"
    assert findings[0].scan_id == result.scan_id


def test_new_findings_get_a_state_row(session):
    result = run_scan(FIXTURE)

    write_scan_results(session, result)
    session.commit()

    states = list(session.scalars(select(FindingState)))
    assert len(states) == 1
    assert states[0].status == FindingStatus.NEW
    assert states[0].suppressed_by is None


def test_suppression_survives_a_rescan(session):
    first = run_scan(FIXTURE)
    write_scan_results(session, first)
    session.commit()

    state = session.scalars(select(FindingState)).one()
    suppressed_id = state.finding_id

    state.status = FindingStatus.SUPPRESSED
    state.suppressed_by = "test-operator"
    state.justification = "Intentionally public for static site hosting"
    state.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    session.commit()

    second = run_scan(FIXTURE)
    assert second.scan_id != first.scan_id

    write_scan_results(session, second)
    session.commit()

    state_after = session.get(FindingState, suppressed_id)

    assert state_after.status == FindingStatus.SUPPRESSED
    assert state_after.suppressed_by == "test-operator"
    assert state_after.justification is not None

    assert len(list(session.scalars(select(FindingState)))) == 1


def test_finding_id_is_stable_across_scans(session):
    first = run_scan(FIXTURE)
    second = run_scan(FIXTURE)

    first_ids = {f.finding_id for r in first.results for f in r.findings}
    second_ids = {f.finding_id for r in second.results for f in r.findings}

    assert first_ids == second_ids
    assert len(first_ids) == 1