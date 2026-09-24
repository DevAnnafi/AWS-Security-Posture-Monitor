from scanner.checks.iam_mfa import IAMMFAEnabledCheck
from scanner.registry import CheckStatus
from scanner.models import Severity
from scanner.fixtures import CREDENTIAL_REPORT_FIXTURE

def test_iam_mfa_enabled_check():
    check = IAMMFAEnabledCheck()
    result = check.evaluate(CREDENTIAL_REPORT_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 1
    assert result.findings[0].resource_id == (
        "arn:aws:iam::157182991517:user/password-only-user"
    )