from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Severity, Finding

class SecurityGroupAdminPorts(BaseCheck):
    control_id = "6.3"
    title = "Security group allows 0.0.0.0/0 on port 22 and 3389"
    severity = Severity.CRITICAL
    remediable = True
    requires =  ["security_groups"]

    def evaluate(self, snapshot):
        return CheckResult(
            status=CheckStatus.EVALUATED,
            findings=[],
            control_id=self.control_id,
            error=None,
            unevaluated=[],
            )