from scanner.registry import BaseCheck, CheckResult, CheckStatus, derive_status
from scanner.models import Finding, Severity
from scanner.collector import CollectionStatus


class CloudTrailMultiRegionLoggingCheck(BaseCheck):
    control_id = "4.1"
    title = "CloudTrail multi-region trail is not logging"
    remediable = False
    requires = ["cloudtrail_trails"]

    def evaluate(self, snapshot) -> CheckResult:
        section = snapshot["cloudtrail_trails"]

        if section["status"] != CollectionStatus.OK.value:
            return CheckResult(
                status=CheckStatus.CANT_EVALUATE,
                findings=[],
                control_id=self.control_id,
                error=section["status"],
                unevaluated=[],
            )

        for region in section["document"]:
            for trail in region["document"]:
                if not trail["is_multi_region_trail"]:
                    continue

                is_logging = trail["is_logging"]

                if is_logging["status"] != CollectionStatus.OK.value:
                    continue

                if is_logging["document"]["IsLogging"] is True:
                    return CheckResult(
                        status=CheckStatus.EVALUATED,
                        findings=[],
                        control_id=self.control_id,
                        error=None,
                        unevaluated=[],
                    )

        finding = Finding(
            control_id=self.control_id,
            title=self.title,
            severity=Severity.HIGH,
            resource_id=snapshot["account_id"],
            resource_sub_id=None,
            region=None,
            remediable=self.remediable,
            evidence={
                "reason": "No multi-region CloudTrail trail is currently logging."
            },
            account_id=snapshot["account_id"],
        )

        findings = [finding]
        unevaluated = []

        return CheckResult(
            status=derive_status(findings, unevaluated),
            findings=findings,
            control_id=self.control_id,
            error=None,
            unevaluated=unevaluated,
        )