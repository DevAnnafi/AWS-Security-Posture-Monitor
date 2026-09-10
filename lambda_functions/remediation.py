from botocore.exceptions import ClientError
from scanner.checks.sg_open_ssh import ADMIN_PORTS


def _is_safe_to_remediate(rule):
    """
    Return True only for public, exact-match TCP admin-port rules.

    Broad port ranges and protocol '-1' are not automatically remediated.
    """
    if rule["IpProtocol"] == "-1":
        return False

    if rule["IpProtocol"] != "tcp":
        return False

    if rule["FromPort"] != rule["ToPort"]:
        return False

    if rule["FromPort"] not in ADMIN_PORTS:
        return False

    for cidr_entry in rule.get("IpRanges", []):
        if cidr_entry.get("CidrIp") == "0.0.0.0/0":
            return True

    return False


def remediate_public_s3_bucket(s3_client, bucket_name):
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        return {"status": "ok"}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "AccessDenied":
            return {
                "status": "access_denied",
                "error_code": error_code,
            }

        raise


def remediate_public_sg_ingress(ec2_client, group_id, ip_permissions):
    """
    Revoke public exact-match admin-port ingress rules.

    Broad ranges and '-1' rules are intentionally left for manual review.
    """
    rules_to_revoke = []

    for rule in ip_permissions:
        if _is_safe_to_remediate(rule):
            if rule not in rules_to_revoke:
                rules_to_revoke.append(rule)

    for rule in rules_to_revoke:
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[rule],
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "InvalidPermission.NotFound":
                # Rule was already removed; remediation is effectively complete.
                continue

            if error_code == "UnauthorizedOperation":
                return {
                    "status": "access_denied",
                    "error_code": error_code,
                }

            raise

    return {
        "status": "ok",
        "revoked_rules": len(rules_to_revoke),
    }

