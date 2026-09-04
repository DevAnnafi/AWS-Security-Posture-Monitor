from scanner.checks.sg_open_ssh import SecurityGroupAdminPorts
from scanner.fixtures import SECURITY_GROUP_FIXTURE, ACCESS_DENIED_FIXTURE, CLEAN_ENVIRONMENT_FIXTURE
from scanner.registry import CheckStatus
from scanner.checks.s3_public_access import S3PublicAccess
from scanner.models import Severity

def test_evaluate_security_group_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(SECURITY_GROUP_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 2
    assert {
        finding.resource_sub_id
        for finding in result.findings
    } == {"22", "3389"}
    assert result.findings[0].severity == Severity.CRITICAL


def test_evaluate_security_group_failed_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(ACCESS_DENIED_FIXTURE)

    assert result.status == CheckStatus.CANT_EVALUATE

def test_evaluate_security_group_clean_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(CLEAN_ENVIRONMENT_FIXTURE)

    assert result.status == CheckStatus.EVALUATED

    assert len(result.findings) == 0
    
    assert len(result.unevaluated) == 0


    