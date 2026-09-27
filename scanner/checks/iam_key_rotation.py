from datetime import datetime, timedelta, timezone

from scanner.registry import BaseCheck, CheckResult, CheckStatus, derive_status
from scanner.models import Finding, Severity
from scanner.collector import CollectionStatus


class IAMKeyRotationCheck(BaseCheck):
    control_id = "2.12"
    title = "Access keys not rotated within 90 days"
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

        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        for user in section["document"]["users"]:
            for slot in (1, 2):
                rotation_field = f"access_key_{slot}_last_rotated"
                active_field = f"access_key_{slot}_active"

                rotated_at = user[rotation_field]

                if rotated_at is None:
                    continue

                if isinstance(rotated_at, str):
                    if rotated_at.endswith("Z"):
                        rotated_at = rotated_at[:-1] + "+00:00"

                    rotated_at = datetime.fromisoformat(rotated_at)

                if rotated_at.tzinfo is None:
                    rotated_at = rotated_at.replace(tzinfo=timezone.utc)

                if rotated_at < threshold:
                    active = user[active_field]

                    findings.append(
                        Finding(
                            control_id=self.control_id,
                            title=self.title,
                            severity=(
                                Severity.LOW
                                if active is True
                                else Severity.INFO
                            ),
                            resource_id=user["arn"],
                            resource_sub_id=f"access_key_{slot}",
                            region=None,
                            remediable=self.remediable,
                            evidence={
                                rotation_field: user[rotation_field],
                                active_field: active,
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