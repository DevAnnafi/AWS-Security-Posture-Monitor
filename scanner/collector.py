from enum import Enum
from botocore.exceptions import ClientError
import boto3
import json


class CollectionStatus(Enum):
    OK = "ok"
    ACCESS_DENIED = "access_denied"
    PARSE_ERROR = "parse_error"


def collect_buckets():
    client = boto3.client("s3")
    response = client.list_buckets()
    return response


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
            # AWS distinguishes no BPA configuration from an explicit
            # all-false configuration. For our CSPM checks, they are
            # operationally equivalent: none of the four protections
            # are enabled. Normalize the absent configuration to all
            # False so consumers always receive boolean BPA flags.
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
            # AWS distinguishes no BPA configuration from an explicit
            # all-false configuration. For our CSPM checks, they are
            # operationally equivalent: none of the four protections
            # are enabled. Normalize the absent configuration to all
            # False so consumers always receive boolean BPA flags.
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

def collect_security_groups(ec2_client):
    try:
        response = ec2_client.describe_security_groups()

        region = ec2_client.meta.region_name

        groups = []

        for group in response["SecurityGroups"]:
            group = dict(group)
            group["region"] = region
            groups.append(group)

        return {
            "status": CollectionStatus.OK.value,
            "document": groups,
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "UnauthorizedOperation":
            return {
                "status": CollectionStatus.ACCESS_DENIED.value,
                "document": None,
            }

        raise

