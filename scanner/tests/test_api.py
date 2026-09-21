from api.db.writer import write_scan_results
from scanner.fixtures import FIXTURE
from scanner.runner import run_scan
from datetime import datetime, timedelta, timezone
from api.db.models import FindingState

def test_findings_endpoint_returns_latest_scan(session, client):
    result = run_scan(FIXTURE)
    write_scan_results(session, result)
    session.commit()

    response = client.get("/findings")

    assert response.status_code == 200
    body = response.json()
    assert body["scan"]["scan_id"] == str(result.scan_id)
    assert len(body["findings"]) == 1
    assert body["findings"][0]["status"] == "new"

def test_suppression_requires_all_fields(session, client):
    result = run_scan(FIXTURE)
    write_scan_results(session, result)
    session.commit()

    finding_id = client.get("/findings").json()["findings"][0]["finding_id"]

    response = client.patch(
        f"/findings/{finding_id}/state",
        json={"status": "suppressed"},
    )

    assert response.status_code == 422


def test_suppressed_findings_are_filtered(session, client):
    result = run_scan(FIXTURE)
    write_scan_results(session, result)
    session.commit()

    finding_id = client.get("/findings").json()["findings"][0]["finding_id"]

    expires_at = datetime.now(timezone.utc) + timedelta(days=1)

    response = client.patch(
        f"/findings/{finding_id}/state",
        json={
            "status": "suppressed",
            "suppressed_by": "attacker",
            "justification": "False positive",
            "expires_at": expires_at.isoformat(),
        },
    )

    assert response.status_code == 200
    assert response.json()["suppressed_by"] == "test@example.com"

    response = client.get("/findings?include_suppressed=false")

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 0

    response = client.get("/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["finding_id"] == finding_id
    assert body["findings"][0]["status"] == "suppressed"


def test_expired_suppression_reads_as_new(session, client):
    result = run_scan(FIXTURE)
    write_scan_results(session, result)
    session.commit()

    finding_id = client.get("/findings").json()["findings"][0]["finding_id"]

    state = session.get(FindingState, finding_id)
    assert state is not None

    state.status = "suppressed"
    state.suppressed_by = "test"
    state.justification = "Expired suppression"
    state.expires_at = datetime.now(timezone.utc) - timedelta(days=1)

    session.commit()

    response = client.get("/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["finding_id"] == finding_id
    assert body["findings"][0]["status"] == "new"

def test_suppression_requires_authentication(anonymous_client):
    expires_at = datetime.now(timezone.utc) + timedelta(days=1)

    response = anonymous_client.patch(
        "/findings/made-up-finding-id/state",
        json={
            "status": "suppressed",
            "justification": "Test authentication requirement",
            "expires_at": expires_at.isoformat(),
        },
    )

    assert response.status_code == 401