from scanner.checks.iam_wildcard_policy import IAMWildcardPolicy
from scanner.fixtures import (
    IAM_WILDCARD_POLICY_FIXTURE,
    IAM_UNATTACHED_WILDCARD_POLICY_FIXTURE,
    IAM_SERVICE_WILDCARD_POLICY_FIXTURE,
    IAM_NOTREADABLE_FIXTURE
)
from scanner.models import Severity
from scanner.registry import CheckStatus


def test_attached_admin_policy_is_a_finding():
    check = IAMWildcardPolicy()

    result = check.evaluate(IAM_WILDCARD_POLICY_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.resource_id == (
        "arn:aws:iam::157182991517:policy/full-admin-policy"
    )
    assert finding.severity == Severity.CRITICAL
    assert finding.region is None


def test_unattached_admin_policy_is_not_a_finding():
    check = IAMWildcardPolicy()

    result = check.evaluate(IAM_UNATTACHED_WILDCARD_POLICY_FIXTURE)

    assert result.status == CheckStatus.EVALUATED
    assert len(result.findings) == 0


def test_service_wildcard_policy_is_not_a_finding():
    check = IAMWildcardPolicy()

    result = check.evaluate(IAM_SERVICE_WILDCARD_POLICY_FIXTURE)

    assert result.status == CheckStatus.EVALUATED
    assert len(result.findings) == 0

def test_iam_section_unreadable_cannot_evaluate():
    check = IAMWildcardPolicy()

    result = check.evaluate(IAM_NOTREADABLE_FIXTURE)

    assert result.status == CheckStatus.CANT_EVALUATE
    assert len(result.findings) == 0

    assert result.error == "access_denied"