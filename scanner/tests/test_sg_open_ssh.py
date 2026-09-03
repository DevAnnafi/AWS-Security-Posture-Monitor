from scanner.checks.sg_open_ssh import SecurityGroupAdminPorts
from scanner.fixtures import SECURITY_GROUP_FIXTURE
from scanner.registry import CheckStatus

def test_evaluate_security_group_fixture():
    check = SecurityGroupAdminPorts()

    result = check.evaluate(SECURITY_GROUP_FIXTURE)

    assert result.status == CheckStatus.VIOLATIONS
    assert len(result.findings) == 2
    assert {
        finding.resource_sub_id
        for finding in result.findings
    } == {"22", "3389"}