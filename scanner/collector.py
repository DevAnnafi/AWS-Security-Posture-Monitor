from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError
from urllib.parse import unquote
import boto3
import json


class CollectionStatus(Enum):
    OK = "ok"
    ACCESS_DENIED = "access_denied"
    PARTIAL = "partial"  
    PARSE_ERROR = "parse_error"


def collect_bucket(s3_client, bucket_name):
    location_response = s3_client.get_bucket_location(
        Bucket=bucket_name
    )
    region = location_response.get("LocationConstraint")

    if region is None:
        region = "us-east-1"

    return {
        "name": bucket_name,
        "region": region,
        "policy": collect_policy(s3_client, bucket_name),
        "acl": collect_acl(s3_client, bucket_name),
        "ownership_controls": collect_ownership_controls(
            s3_client,
            bucket_name,
        ),
        "bucket_bpa": collect_bucket_bpa(
            s3_client,
            bucket_name,
        ),
    }


def collect_policy(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        document = json.loads(response["Policy"])

        return {
            "status": CollectionStatus.OK.value,
            "document": document,
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchBucketPolicy":
            return {
                "status": CollectionStatus.OK.value,
                "document": None,
            }

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise

    except json.JSONDecodeError:
        return {
            "status": CollectionStatus.PARSE_ERROR.value,
            "document": None,
        }


def collect_acl(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)

        return {
            "status": CollectionStatus.OK.value,
            "document": {
                "Owner": response["Owner"],
                "Grants": response["Grants"],
            },
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise


def collect_ownership_controls(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_ownership_controls(
            Bucket=bucket_name
        )

        return {
            "status": CollectionStatus.OK.value,
            "document": response["OwnershipControls"],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "OwnershipControlsNotFoundError":
            return {
                "status": CollectionStatus.OK.value,
                "document": None,
            }

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise


def collect_bucket_bpa(s3_client, bucket_name):
    try:
        response = s3_client.get_public_access_block(
            Bucket=bucket_name
        )

        return {
            "status": CollectionStatus.OK.value,
            "document": response["PublicAccessBlockConfiguration"],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "status": CollectionStatus.OK.value,
                "document": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            }

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise


def collect_account_bpa(s3control_client, account_id):
    try:
        response = s3control_client.get_public_access_block(
            AccountId=account_id
        )

        return {
            "status": CollectionStatus.OK.value,
            "document": response["PublicAccessBlockConfiguration"],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "status": CollectionStatus.OK.value,
                "document": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            }

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise


def collect_iam(iam_client):
    try:
        paginator = iam_client.get_paginator("list_policies")

        policies = []

        for page in paginator.paginate(
            Scope="Local",
            OnlyAttached=False,
        ):
            for policy in page["Policies"]:
                try:
                    response = iam_client.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )

                    document = response["PolicyVersion"]["Document"]

                    if isinstance(document, str):
                        document = json.loads(unquote(document))

                    document_status = {
                        "status": CollectionStatus.OK.value,
                        "document": document,
                    }

                except ClientError as e:
                    error_code = e.response["Error"]["Code"]

                    if error_code == "AccessDenied":
                        document_status = {
                            "status": CollectionStatus.ACCESS_DENIED.value,
                            "document": None,
                        }
                    else:
                        raise

                except json.JSONDecodeError:
                    document_status = {
                        "status": CollectionStatus.PARSE_ERROR.value,
                        "document": None,
                    }

                policies.append({
                    "name": policy["PolicyName"],
                    "arn": policy["Arn"],
                    "attachment_count": policy["AttachmentCount"],
                    "document": document_status,
                })

        return {
            "status": CollectionStatus.OK.value,
            "document": policies,
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "AccessDenied":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise


def collect_security_groups(regions):
    document = []

    for region in regions:
        ec2_client = boto3.client(
            "ec2",
            region_name=region,
        )

        try:
            response = ec2_client.describe_security_groups()

            groups = []

            for group in response["SecurityGroups"]:
                group = dict(group)
                group["region"] = region
                groups.append(group)

            document.append({
                "region": region,
                "status": CollectionStatus.OK.value,
                "document": groups,
            })

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "UnauthorizedOperation":
                document.append({
                    "region": region,
                    "status": CollectionStatus.ACCESS_DENIED.value,
                    "document": None,
                })
            else:
                raise

    if not document:
        status = CollectionStatus.ACCESS_DENIED.value
    elif all(
        entry["status"] == CollectionStatus.OK.value
        for entry in document
    ):
        status = CollectionStatus.OK.value
    elif all(
        entry["status"] == CollectionStatus.ACCESS_DENIED.value
        for entry in document
    ):
        status = CollectionStatus.ACCESS_DENIED.value
    else:
        status = CollectionStatus.PARTIAL.value

    return {
        "status": status,
        "document": document,
    }


def collect_snapshot():
    s3_client = boto3.client("s3")
    s3control_client = boto3.client("s3control")
    iam_client = boto3.client("iam")
    sts_client = boto3.client("sts")

    account_id = sts_client.get_caller_identity()["Account"]

    # TODO: Discover/configure all regions instead of hardcoding.
    regions = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]

    regions_covered = regions

    try:
        bucket_response = s3_client.list_buckets()
        s3_status = CollectionStatus.OK.value

        bucket_names = [
            bucket["Name"]
            for bucket in bucket_response["Buckets"]
        ]

        with ThreadPoolExecutor(max_workers=10) as executor:
            buckets = list(
                executor.map(
                    lambda name: collect_bucket(
                        s3_client,
                        name,
                    ),
                    bucket_names,
                )
            )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "AccessDenied":
            s3_status = CollectionStatus.ACCESS_DENIED.value
            buckets = None
        else:
            raise

    return {
        "account_id": account_id,
        "regions_covered": regions_covered,

        "s3_buckets": {
            "status": s3_status,
            "document": buckets,
        },

        "iam_policies": collect_iam(iam_client),

        "account_bpa": collect_account_bpa(
            s3control_client,
            account_id,
        ),

        "security_groups": collect_security_groups(
            regions,
        ),
    }