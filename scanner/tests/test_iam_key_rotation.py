from scanner.models import Severity
from scanner.registry import CheckStatus
from scanner.checks.iam_key_rotation import IAMKeyRotationCheck
from scanner.fixtures import KEY_ROTATION_FIXTURE


def test_iam_key_rotation_check():
    result = IAMKeyRotationCheck().evaluate(KEY_ROTATION_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 4

    active_stale = next(
        finding
        for finding in result.findings
        if finding.resource_id.endswith("/active-stale-key-user")
    )
    assert active_stale.severity == Severity.LOW

    inactive_stale = next(
        finding
        for finding in result.findings
        if finding.resource_id.endswith("/inactive-stale-key-user")
    )
    assert inactive_stale.severity == Severity.INFO

    both_stale = [
        finding
        for finding in result.findings
        if finding.resource_id.endswith("/both-stale-keys-user")
    ]

    assert len(both_stale) == 2
    assert {
        finding.resource_sub_id
        for finding in both_stale
    } == {"access_key_1", "access_key_2"}