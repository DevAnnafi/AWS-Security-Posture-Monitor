import json
import os

import boto3
from botocore.exceptions import ClientError

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


sns_client = boto3.client("sns")


def publish_remediation_notification(
    event,
    resource,
    control_id,
    remediation_result,
):
    """
    Publish an SNS notification after a remediation attempt.

    SNS failures are handled separately from remediation failures so that
    a successful remediation is not incorrectly reported as failed just
    because the notification could not be delivered.
    """
    topic_arn = os.environ["SNS_TOPIC_ARN"]

    detail = event.get("detail", {})
    identity = detail.get("userIdentity", {})

    message = {
        "message": "CSPM remediation attempted",
        "resource": resource,
        "control_id": control_id,
        "event": {
            "eventName": detail.get("eventName"),
            "eventSource": detail.get("eventSource"),
            "eventTime": detail.get("eventTime"),
            "region": detail.get("awsRegion"),
        },
        "triggered_by": {
            "type": identity.get("type"),
            "arn": identity.get("arn"),
            "userName": identity.get("userName"),
        },
        "remediation": remediation_result,
    }

    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject="CSPM remediation attempted",
            Message=json.dumps(message, default=str),
        )

        return {
            "status": "ok",
            "message_id": response.get("MessageId"),
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        print(
            f"SNS notification failed for resource {resource}: "
            f"{error_code}"
        )

        return {
            "status": "failed",
            "error_code": error_code,
        }


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
    #
    # These must match the EventBridge Terraform rule.
    # ---------------------------------------------------------

    s3_events = {
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl",
    }

    if event_name in s3_events:
        bucket_name = params.get("bucketName")

        if not bucket_name:
            print(
                f"Ignoring {event_name}: no bucketName"
            )

            return {
                "status": "ignored",
                "reason": "missing bucketName",
            }

        print(
            f"S3 event: {event_name}, "
            f"bucket: {bucket_name}"
        )

        # -----------------------------------------------------
        # Re-scan bucket.
        # -----------------------------------------------------

        snapshot = collect_bucket_snapshot(
            s3_client,
            s3control_client,
            account_id,
            bucket_name,
        )

        check_result = S3PublicAccess().evaluate(snapshot)

        print(
            f"S3 check result: {check_result}"
        )

        # -----------------------------------------------------
        # No violation.
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
        # Remediation.
        # -----------------------------------------------------

        remediation_result = remediate_public_s3_bucket(
            s3_client,
            bucket_name,
        )

        # -----------------------------------------------------
        # Notify only after an actual remediation attempt.
        # -----------------------------------------------------

        notification_result = publish_remediation_notification(
            event=event,
            resource=bucket_name,
            control_id=check_result.control_id,
            remediation_result=remediation_result,
        )

        print(f"Remediation result: {remediation_result}")

        print(f"Notification result: {notification_result}")

        # -----------------------------------------------------
        # Return accurate top-level status.
        # -----------------------------------------------------

        if remediation_result["status"] == "ok":
            status = "remediated"
        else:
            status = "remediation_failed"

        return {
            "status": status,
            "resource": bucket_name,
            "check_status": check_result.status.value,
            "finding_count": len(check_result.findings),
            "remediation": remediation_result,
            "notification": notification_result,
        }

    # ---------------------------------------------------------
    # Security Group events
    #
    # Only AuthorizeSecurityGroupIngress can create the
    # condition we currently detect.
    # ---------------------------------------------------------

    if event_name == "AuthorizeSecurityGroupIngress":
        group_id = params.get("groupId")

        if not group_id:
            print(
                f"Ignoring {event_name}: no groupId"
            )

            return {
                "status": "ignored",
                "reason": "missing groupId",
            }

        print(
            f"Security Group event: {event_name}, "
            f"group: {group_id}"
        )

        # -----------------------------------------------------
        # Re-scan security group.
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
        # Evaluate current state.
        # -----------------------------------------------------

        check_result = SecurityGroupAdminPorts().evaluate(
            snapshot
        )

        print(
            f"Security Group check result: {check_result}"
        )

        # -----------------------------------------------------
        # No violation.
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
        # Get current IpPermissions.
        # -----------------------------------------------------

        group = snapshot[
            "security_groups"
        ][
            "document"
        ][0][
            "document"
        ][0]

        ip_permissions = group["IpPermissions"]

        # -----------------------------------------------------
        # Remediate.
        # -----------------------------------------------------

        remediation_result = remediate_public_sg_ingress(
            ec2_client,
            group_id,
            ip_permissions,
        )

        # -----------------------------------------------------
        # Notify after remediation attempt.
        # -----------------------------------------------------

        notification_result = publish_remediation_notification(
            event=event,
            resource=group_id,
            control_id=check_result.control_id,
            remediation_result=remediation_result,
        )

        print(f"Remediation result: {remediation_result}")

        print(f"Notification result: {notification_result}")

        # -----------------------------------------------------
        # Return accurate top-level status.
        # -----------------------------------------------------

        if remediation_result["status"] == "ok":
            status = "remediated"
        else:
            status = "remediation_failed"

        return {
            "status": status,
            "resource": group_id,
            "check_status": check_result.status.value,
            "finding_count": len(check_result.findings),
            "remediation": remediation_result,
            "notification": notification_result,
        }

    # ---------------------------------------------------------
    # Anything else is ignored.
    # ---------------------------------------------------------

    print(
        f"Ignoring unrecognized event: {event_name}"
    )

    return {
        "status": "ignored",
        "eventName": event_name,
    }

