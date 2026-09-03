from scanner.checks.sg_open_ssh import SecurityGroupAdminPorts
from scanner.fixtures import SECURITY_GROUP_FIXTURE, ACCESS_DENIED_FIXTURE, S3_NOTREADABLE_FIXTURE
from scanner.registry import CheckStatus
from scanner.checks.s3_public_access import S3PublicAccess

def test_evaluate_security_group_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(SECURITY_GROUP_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 2
    assert {
        finding.resource_sub_id
        for finding in result.findings
    } == {"22", "3389"}


def test_evaluate_security_group_failed_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(ACCESS_DENIED_FIXTURE)

    assert result.status == CheckStatus.CANT_EVALUATE

def test_evaluate_s3_notreadable_fixture():
    check = S3PublicAccess()

    result = check.evaluate(S3_NOTREADABLE_FIXTURE)

    assert result.status == CheckStatus.CANT_EVALUATE
    