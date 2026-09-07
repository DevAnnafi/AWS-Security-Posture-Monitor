from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Finding, Severity
from scanner.collector import CollectionStatus


def _grants_full_admin(document):
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions and "*" in resources:
            return True

    return False


class IAMWildcardPolicy(BaseCheck):
    control_id = "2.14"
    title = "IAM Policy Grants Full Admin Privileges"
    remediable = True
    requires = ["iam_policies"]

    def evaluate(self, snapshot):
        section = snapshot["iam_policies"]

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

        for policy in section["document"]:
            document = policy["document"]

            if document["status"] != CollectionStatus.OK.value:
                unevaluated.append(
                    {
                        "target_type": "policy",
                        "target": policy["arn"],
                        "value": "document",
                        "reason": document["status"],
                    }
                )
                continue

            document = document["document"]

            if policy["attachment_count"] <= 0:
                continue

            if _grants_full_admin(document):
                findings.append(
                    Finding(
                        control_id=self.control_id,
                        resource_id=policy["arn"],
                        resource_sub_id=None,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        remediable=self.remediable,
                        evidence=document,
                        account_id=snapshot["account_id"],
                        region=None,
                    )
                )

        if unevaluated:
            status = CheckStatus.PARTIAL
        elif findings:
            status = CheckStatus.VIOLATIONS
        else:
            status = CheckStatus.EVALUATED

        return CheckResult(
            status=status,
            findings=findings,
            control_id=self.control_id,
            error=None,
            unevaluated=unevaluated,
        )