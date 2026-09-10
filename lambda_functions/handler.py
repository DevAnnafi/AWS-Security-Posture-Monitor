import boto3

from scanner.checks.s3_public_access import S3PublicAccess
from scanner.checks.sg_open_ssh import SecurityGroupAdminPorts
from lambda_functions.remediation import remediate_public_s3_bucket
from lambda_functions.remediation import remediate_public_sg_ingress

from scanner.collector import (
    collect_bucket,
    collect_account_bpa,
    CollectionStatus,
    collect_security_group,
)
from scanner.registry import CheckStatus


def collect_bucket_snapshot(
    s3_client,
    s3control_client,
    account_id,
    bucket_name,
):
    bucket = collect_bucket(
        s3_client,
        bucket_name,
    )

    account_bpa = collect_account_bpa(
        s3control_client,
        account_id,
    )

    return {
        "account_id": account_id,
        "regions_covered": [
            bucket["region"],
        ],
        "s3_buckets": {
            "status": CollectionStatus.OK.value,
            "document": [bucket],
        },
        "account_bpa": account_bpa,
    }


def collect_security_group_snapshot(
    ec2_client,
    account_id,
    group_id,
):
    result = collect_security_group(
        ec2_client,
        group_id,
    )

    if result["status"] == CollectionStatus.NOT_FOUND.value:
        return None

    region = ec2_client.meta.region_name

    return {
        "account_id": account_id,
        "regions_covered": [
            region,
        ],
        "security_groups": {
            "status": result["status"],
            "document": [
                {
                    "region": region,
                    "status": result["status"],
                    "document": [result["document"]],
                }
            ],
        },
    }


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    params = detail.get("requestParameters", {})

    # ---------------------------------------------------------
    # Create clients
    # ---------------------------------------------------------
    s3_client = boto3.client("s3")
    s3control_client = boto3.client("s3control")
    ec2_client = boto3.client("ec2")
    sts_client = boto3.client("sts")

    account_id = sts_client.get_caller_identity()["Account"]

    # ---------------------------------------------------------
    # S3 events
    # ---------------------------------------------------------
    s3_events = {
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "DeleteBucketAcl",
    }

    if event_name in s3_events:
        bucket_name = params.get("bucketName")

        if not bucket_name:
            print(f"Ignoring {event_name}: no bucketName")
            return {
                "status": "ignored",
                "reason": "missing bucketName",
            }

        print(f"S3 event: {event_name}, bucket: {bucket_name}")

        # -----------------------------------------------------
        # Re-scan this bucket.
        # -----------------------------------------------------
        snapshot = collect_bucket_snapshot(
            s3_client,
            s3control_client,
            account_id,
            bucket_name,
        )

        check_result = S3PublicAccess().evaluate(snapshot)

        print(f"S3 check result: {check_result}")

        # -----------------------------------------------------
        # Only remediate if the bucket is still violating.
        # -----------------------------------------------------
        if check_result.status != CheckStatus.VIOLATIONS:
            print(
                f"Bucket {bucket_name} is not currently public. "
                "No remediation needed."
            )

            return {
                "status": "no_remediation",
                "resource": bucket_name,
                "check_status": check_result.status.value,
                "finding_count": len(check_result.findings),
            }

        # -----------------------------------------------------
        # Remediate the confirmed finding.
        # -----------------------------------------------------
        remediation_result = remediate_public_s3_bucket(
            s3_client,
            bucket_name,
        )

        return {
            "status": "remediated",
            "resource": bucket_name,
            "check_status": check_result.status.value,
            "finding_count": len(check_result.findings),
            "remediation": remediation_result,
        }

    # ---------------------------------------------------------
    # Security Group events
    # ---------------------------------------------------------
    security_group_events = {
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
    }

    if event_name in security_group_events:
        group_id = params.get("groupId")

        if not group_id:
            print(f"Ignoring {event_name}: no groupId")
            return {
                "status": "ignored",
                "reason": "missing groupId",
            }

        print(
            f"Security Group event: {event_name}, "
            f"group: {group_id}"
        )

        # -----------------------------------------------------
        # Re-scan this security group.
        # -----------------------------------------------------
        snapshot = collect_security_group_snapshot(
            ec2_client,
            account_id,
            group_id,
        )

        # -----------------------------------------------------
        # Group was deleted between the event and invocation.
        # -----------------------------------------------------
        if snapshot is None:
            print(
                f"Security Group {group_id} no longer exists. "
                "No remediation needed."
            )

            return {
                "status": "not_found",
                "resource": group_id,
            }

        # -----------------------------------------------------
        # Evaluate the current state.
        # -----------------------------------------------------
        check_result = SecurityGroupAdminPorts().evaluate(snapshot)

        print(f"Security Group check result: {check_result}")

        # -----------------------------------------------------
        # Only remediate if the group is still violating.
        # -----------------------------------------------------
        if check_result.status != CheckStatus.VIOLATIONS:
            print(
                f"Security Group {group_id} is not currently "
                "violating. No remediation needed."
            )

            return {
                "status": "no_remediation",
                "resource": group_id,
                "check_status": check_result.status.value,
                "finding_count": len(check_result.findings),
            }

        # -----------------------------------------------------
        # Get the current IpPermissions from the snapshot.
        # -----------------------------------------------------
        group = snapshot["security_groups"]["document"][0]["document"][0]

        ip_permissions = group["IpPermissions"]

        # -----------------------------------------------------
        # Remediate the confirmed finding.
        # -----------------------------------------------------
        remediation_result = remediate_public_sg_ingress(
            ec2_client,
            group_id,
            ip_permissions,
        )

        return {
            "status": "remediated",
            "resource": group_id,
            "check_status": check_result.status.value,
            "finding_count": len(check_result.findings),
            "remediation": remediation_result,
        }

    # ---------------------------------------------------------
    # Anything else is ignored.
    # ---------------------------------------------------------
    print(f"Ignoring unrecognized event: {event_name}")

    return {
        "status": "ignored",
        "eventName": event_name,
    }

