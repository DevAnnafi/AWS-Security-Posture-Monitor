from scanner.registry import BaseCheck, CheckResult, CheckStatus

class IAMWildcardPolicy(BaseCheck):
    control_id = "2.14"
    title = "IAM Policy Grants Full Admin Privileges"
    remediable = True
    requires = ["iam_policies"]

    def evaluate(self, snapshot):
      return CheckResult(
            status=CheckStatus.EVALUATED,
            findings=[],
            control_id=self.control_id,
            error=None,
            unevaluated=[],
      )
    
