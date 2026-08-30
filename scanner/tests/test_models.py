"""TODO: unit tests. Mock AWS with moto or botocore.stub.Stubber so the
suite runs in CI without live credentials.
"""
from scanner.models import Finding, Severity
import json


def test_finding_round_trips_through_json():
    f = Finding(
        control_id="3.1.4",
        title="S3 bucket publicly accessible",
        severity=Severity.CRITICAL,
        resource_id="arn:aws:s3:::annafi-lab-public",
        resource_sub_id=None,
        region="us-east-1",
        remediable=True,
        evidence={"policy": {"Statement": [{"Principal": "*"}]}},
        account_id="123456789012",
    )
    back = Finding.from_dict(json.loads(json.dumps(f.to_dict())))
    assert back == f