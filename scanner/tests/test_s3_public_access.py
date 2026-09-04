"""
| Bucket       | Public via Policy                                | Public via ACL                                                                         | Overall check                |
| ------------ | ------------------------------------------------ | -------------------------------------------------------------------------------------- | ---------------------------- |
| **bucket-a** | **Yes** — `Principal: "*"` with `s3:GetObject`   | **No** — no public/group grantee; `external-user-id-67890` is a specific CanonicalUser | **Public**                   |
| **bucket-b** | **No** — `document` is `None`                    | **No** — only the owner has `FULL_CONTROL`                                             | **Not public**               |
| **bucket-c** | **Unknown / cannot determine** — `access_denied` | **Unknown / cannot determine** — `access_denied`                                       | **Cannot determine / error** |
"""

from scanner.checks.s3_public_access import S3PublicAccess
from scanner.fixtures import FIXTURE, CLEAN_ENVIRONMENT_FIXTURE, S3_NOTREADABLE_FIXTURE, S3_EVERYTHING_FIXTURE
from scanner.registry import CheckStatus
from scanner.models import Severity

def test_s3_public_access():
    check = S3PublicAccess()

    result = check.evaluate(FIXTURE)

    

    assert result.status == CheckStatus.PARTIAL

    assert len(result.findings) == 1
    assert result.findings[0].resource_id == "arn:aws:s3:::bucket-a"

    assert len(result.unevaluated) == 1
    assert result.unevaluated[0]["resource_id"] == "arn:aws:s3:::bucket-c"

def test_s3_clean_environment():
    check = S3PublicAccess()

    result = check.evaluate(CLEAN_ENVIRONMENT_FIXTURE)

    assert result.status == CheckStatus.EVALUATED

    assert len(result.findings) == 0

    assert len(result.unevaluated) == 0

def test_evaluate_s3_notreadable_fixture():
    check = S3PublicAccess()

    result = check.evaluate(S3_NOTREADABLE_FIXTURE)

    assert result.status == CheckStatus.CANT_EVALUATE

def test_policy_severity_read_only():
    check = S3PublicAccess()
    result = check.evaluate(FIXTURE)

    assert result.findings[0].severity == Severity.MEDIUM

def test_policy_severity_everything():
    check = S3PublicAccess()
    result = check.evaluate(S3_EVERYTHING_FIXTURE)

    assert result.findings[0].severity == Severity.HIGH