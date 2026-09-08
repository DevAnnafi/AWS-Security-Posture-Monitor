import json

import boto3
from botocore.stub import Stubber

from scanner.collector import (
    CollectionStatus,
    collect_account_bpa,
    collect_acl,
    collect_bucket_bpa,
    collect_iam,
    collect_ownership_controls,
    collect_policy,
)


# ============================================================
# collect_policy
# ============================================================

def test_collect_policy_returns_parsed_document():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        ],
    }

    stubber.add_response(
        "get_bucket_policy",
        {
            "Policy": json.dumps(policy),
        },
        {
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_policy(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": policy,
    }

    stubber.deactivate()


def test_collect_policy_no_policy():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_policy(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": None,
    }

    stubber.deactivate()


def test_collect_policy_access_denied():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="AccessDenied",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_policy(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.ACCESS_DENIED.value,
        "document": None,
    }

    stubber.deactivate()


def test_collect_policy_invalid_json():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_response(
        "get_bucket_policy",
        {
            "Policy": "this-is-not-valid-json",
        },
        {
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_policy(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.PARSE_ERROR.value,
        "document": None,
    }

    stubber.deactivate()


# ============================================================
# collect_acl
# ============================================================

def test_collect_acl_returns_owner_and_grants():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    owner = {
        "DisplayName": "test-user",
        "ID": "owner-id",
    }

    grants = [
        {
            "Grantee": {
                "Type": "CanonicalUser",
                "ID": "owner-id",
            },
            "Permission": "FULL_CONTROL",
        }
    ]

    stubber.add_response(
        "get_bucket_acl",
        {
            "Owner": owner,
            "Grants": grants,
        },
        {
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_acl(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": {
            "Owner": owner,
            "Grants": grants,
        },
    }

    stubber.deactivate()


def test_collect_acl_access_denied():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_bucket_acl",
        service_error_code="AccessDenied",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_acl(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.ACCESS_DENIED.value,
        "document": None,
    }

    stubber.deactivate()


# ============================================================
# collect_ownership_controls
# ============================================================

def test_collect_ownership_controls_returns_configuration():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    ownership_controls = {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerEnforced",
            }
        ]
    }

    stubber.add_response(
        "get_bucket_ownership_controls",
        {
            "OwnershipControls": ownership_controls,
        },
        {
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_ownership_controls(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": ownership_controls,
    }

    stubber.deactivate()


def test_collect_ownership_controls_not_found():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_bucket_ownership_controls",
        service_error_code="OwnershipControlsNotFoundError",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_ownership_controls(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": None,
    }

    stubber.deactivate()


def test_collect_ownership_controls_access_denied():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_bucket_ownership_controls",
        service_error_code="AccessDenied",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_ownership_controls(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.ACCESS_DENIED.value,
        "document": None,
    }

    stubber.deactivate()


# ============================================================
# collect_bucket_bpa
# ============================================================

def test_collect_bucket_bpa_returns_configuration():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": configuration,
        },
        {
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_bucket_bpa(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": configuration,
    }

    stubber.deactivate()


def test_collect_bucket_bpa_no_configuration():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_bucket_bpa(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    }

    stubber.deactivate()


def test_collect_bucket_bpa_access_denied():
    client = boto3.client("s3", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        expected_params={
            "Bucket": "my-bucket",
        },
    )

    stubber.activate()

    result = collect_bucket_bpa(client, "my-bucket")

    assert result == {
        "status": CollectionStatus.ACCESS_DENIED.value,
        "document": None,
    }

    stubber.deactivate()


# ============================================================
# collect_account_bpa
# ============================================================

def test_collect_account_bpa_returns_configuration():
    client = boto3.client("s3control", region_name="us-east-1")
    stubber = Stubber(client)

    configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": True,
    }

    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": configuration,
        },
        {
            "AccountId": "123456789012",
        },
    )

    stubber.activate()

    result = collect_account_bpa(client, "123456789012")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": configuration,
    }

    stubber.deactivate()


def test_collect_account_bpa_no_configuration():
    client = boto3.client("s3control", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        expected_params={
            "AccountId": "123456789012",
        },
    )

    stubber.activate()

    result = collect_account_bpa(client, "123456789012")

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    }

    stubber.deactivate()


def test_collect_account_bpa_access_denied():
    client = boto3.client("s3control", region_name="us-east-1")
    stubber = Stubber(client)

    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="AccessDenied",
        expected_params={
            "AccountId": "123456789012",
        },
    )

    stubber.activate()

    result = collect_account_bpa(client, "123456789012")

    assert result == {
        "status": CollectionStatus.ACCESS_DENIED.value,
        "document": None,
    }

    stubber.deactivate()


# ============================================================
# collect_iam
# ============================================================

def test_collect_iam_returns_policies():
    client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(client)

    policies = [
        {
            "PolicyName": "TestPolicy",
            "Arn": "arn:aws:iam::123456789012:policy/TestPolicy",
            "AttachmentCount": 1,
            "DefaultVersionId": "v1",
        }
    ]

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    stubber.add_response(
        "list_policies",
        {
            "Policies": policies,
            "IsTruncated": False,
        },
        {
            "Scope": "Local",
            "OnlyAttached": False,
        },
    )

    stubber.add_response(
        "get_policy_version",
        {
            "PolicyVersion": {
                "Document": json.dumps(policy_document),
            }
        },
        {
            "PolicyArn": policies[0]["Arn"],
            "VersionId": "v1",
        },
    )

    stubber.activate()

    result = collect_iam(client)

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": [
            {
                "name": "TestPolicy",
                "arn": policies[0]["Arn"],
                "attachment_count": 1,
                "document": {
                    "status": CollectionStatus.OK.value,
                    "document": policy_document,
                },
            }
        ],
    }

    stubber.deactivate()

def test_collect_iam_policy_access_denied():
    client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(client)

    policy = {
        "PolicyName": "RestrictedPolicy",
        "Arn": "arn:aws:iam::123456789012:policy/RestrictedPolicy",
        "AttachmentCount": 0,
        "DefaultVersionId": "v1",
    }

    stubber.add_response(
        "list_policies",
        {
            "Policies": [policy],
            "IsTruncated": False,
        },
        {
            "Scope": "Local",
            "OnlyAttached": False,
        },
    )

    stubber.add_client_error(
        "get_policy_version",
        service_error_code="AccessDenied",
        expected_params={
            "PolicyArn": policy["Arn"],
            "VersionId": "v1",
        },
    )

    stubber.activate()

    result = collect_iam(client)

    assert result == {
        "status": CollectionStatus.OK.value,
        "document": [
            {
                "name": "RestrictedPolicy",
                "arn": policy["Arn"],
                "attachment_count": 0,
                "document": {
                    "status": CollectionStatus.ACCESS_DENIED.value,
                    "document": None,
                },
            }
        ],
    }

    stubber.deactivate()


def test_collect_iam_policy_invalid_json():
    client = boto3.client("iam", region_name="us-east-1")
    stubber = Stubber(client)

    policy = {
        "PolicyName": "BadPolicy",
        "Arn": "arn:aws:iam::123456789012:policy/BadPolicy",
        "AttachmentCount": 0,
        "DefaultVersionId": "v1",
    }

    stubber.add_response(
        "list_policies",
        {
            "Policies": [policy],
            "IsTruncated": False,
        },
        {
            "Scope": "Local",
            "OnlyAttached": False,
        },
    )

    stubber.add_response(
        "get_policy_version",
        {
            "PolicyVersion": {
                "Document": "not-json",
            }
        },
        {
            "PolicyArn": policy["Arn"],
            "VersionId": "v1",
        },
    )

    stubber.activate()

    result = collect_iam(client)

    assert result["status"] == CollectionStatus.OK.value
    assert result["document"][0]["document"] == {
        "status": CollectionStatus.PARSE_ERROR.value,
        "document": None,
    }

    stubber.deactivate()