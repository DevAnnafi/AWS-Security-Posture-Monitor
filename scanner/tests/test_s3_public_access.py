"""
| Bucket       | Public via Policy                                | Public via ACL                                                                         | Overall check                |
| ------------ | ------------------------------------------------ | -------------------------------------------------------------------------------------- | ---------------------------- |
| **bucket-a** | **Yes** — `Principal: "*"` with `s3:GetObject`   | **No** — no public/group grantee; `external-user-id-67890` is a specific CanonicalUser | **Public**                   |
| **bucket-b** | **No** — `document` is `None`                    | **No** — only the owner has `FULL_CONTROL`                                             | **Not public**               |
| **bucket-c** | **Unknown / cannot determine** — `access_denied` | **Unknown / cannot determine** — `access_denied`                                       | **Cannot determine / error** |
"""

from scanner.checks.s3_public_access import S3PublicAccess
from scanner.fixtures import FIXTURE
from scanner.registry import CheckStatus

def test_s3_public_access():
    check = S3PublicAccess()

    result = check.evaluate(FIXTURE)

    assert result.status == CheckStatus.PARTIAL

    assert len(result.findings) == 1
    assert result.findings[0].resource_id == "arn:aws:s3:::bucket-a"

    assert len(result.unevaluated) == 1
    assert result.unevaluated[0]["resource_id"] == "arn:aws:s3:::bucket-c"