import boto3
from botocore.stub import Stubber
from lambda_functions.remediation import remediate_public_s3_bucket, remediate_public_sg_ingress

def test_remediate_public_s3_bucket():
    s3_client = boto3.client("s3", region_name="us-east-1")

    stubber = Stubber(s3_client)

    stubber.add_response(
        "put_public_access_block",
        {},
        expected_params={
            "Bucket": "my-test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )

    with stubber:
        result = remediate_public_s3_bucket(
            s3_client,
            "my-test-bucket",
        )

    stubber.assert_no_pending_responses()

    assert result == {"status": "ok"}

def test_remediate_public_s3_bucket_access_denied():
    s3_client = boto3.client("s3", region_name="us-east-1")

    stubber = Stubber(s3_client)

    stubber.add_client_error(
        "put_public_access_block",
        service_error_code="AccessDenied",
        expected_params={
            "Bucket": "my-test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )

    with stubber:
        result = remediate_public_s3_bucket(
            s3_client,
            "my-test-bucket",
        )

    stubber.assert_no_pending_responses()

    assert result == {
        "status": "access_denied",
        "error_code": "AccessDenied",
    }

def test_remediate_public_sg_ingress_revokes_admin_ports():
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    stubber = Stubber(ec2_client)

    ssh_rule = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    rdp_rule = {
        "IpProtocol": "tcp",
        "FromPort": 3389,
        "ToPort": 3389,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    https_rule = {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    stubber.add_response(
        "revoke_security_group_ingress",
        {},
        expected_params={
            "GroupId": "sg-123",
            "IpPermissions": [ssh_rule],
        },
    )

    stubber.add_response(
        "revoke_security_group_ingress",
        {},
        expected_params={
            "GroupId": "sg-123",
            "IpPermissions": [rdp_rule],
        },
    )

    with stubber:
        result = remediate_public_sg_ingress(
            ec2_client,
            "sg-123",
            [ssh_rule, rdp_rule, https_rule],
        )

    stubber.assert_no_pending_responses()

    assert result == {
        "status": "ok",
        "revoked_rules": 2,
    }

def test_remediate_public_sg_ingress_skips_broad_range():
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    stubber = Stubber(ec2_client)

    broad_rule = {
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 65535,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    with stubber:
        result = remediate_public_sg_ingress(
            ec2_client,
            "sg-123",
            [broad_rule],
        )

    stubber.assert_no_pending_responses()

    assert result == {
        "status": "ok",
        "revoked_rules": 0,
    }

def test_remediate_public_sg_ingress_skips_all_protocols():
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    stubber = Stubber(ec2_client)

    all_protocols_rule = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    with stubber:
        result = remediate_public_sg_ingress(
            ec2_client,
            "sg-123",
            [all_protocols_rule],
        )

    stubber.assert_no_pending_responses()

    assert result == {
        "status": "ok",
        "revoked_rules": 0,
    }

def test_remediate_public_sg_ingress_already_revoked():
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    stubber = Stubber(ec2_client)

    ssh_rule = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }

    stubber.add_client_error(
        "revoke_security_group_ingress",
        service_error_code="InvalidPermission.NotFound",
        expected_params={
            "GroupId": "sg-123",
            "IpPermissions": [ssh_rule],
        },
    )

    with stubber:
        result = remediate_public_sg_ingress(
            ec2_client,
            "sg-123",
            [ssh_rule],
        )

    stubber.assert_no_pending_responses()

    assert result == {
        "status": "ok",
        "revoked_rules": 1,
    }