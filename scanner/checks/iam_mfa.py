from scanner.registry import BaseCheck, CheckResult, CheckStatus, derive_status
from scanner.models import Finding, Severity
from scanner.collector import CollectionStatus


class IAMMFAEnabledCheck(BaseCheck):
    control_id = "2.10"
    title = "IAM console users should have MFA enabled"
    remediable = False
    requires = ["credential_report"]

    def evaluate(self, snapshot) -> CheckResult:
        section = snapshot["credential_report"]

        if section["status"] != CollectionStatus.OK.value:
            return CheckResult(
                status=CheckStatus.CANT_EVALUATE,
                findings=[],
                control_id=self.control_id,
                error=section["status"],
                unevaluated=[],
            )

        findings = []
        unevaluated = []

        for user in section["document"]["users"]:
            if user["password_enabled"] and not user["mfa_active"]:
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        title=self.title,
                        severity=Severity.LOW,
                        resource_id=user["arn"],
                        resource_sub_id=None,
                        region=None,
                        remediable=self.remediable,
                        evidence={
                            "password_enabled": user["password_enabled"],
                            "mfa_active": user["mfa_active"],
                        },
                        account_id=snapshot["account_id"],
                    )
                )

        status = derive_status(findings, unevaluated)

        return CheckResult(
            status=status,
            findings=findings,
            control_id=self.control_id,
            error=None,
            unevaluated=unevaluated,
        )