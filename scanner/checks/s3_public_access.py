"""CIS check: 2.1.5 - S3 bucket publicly accessible.

TODO: implement. Declare the control ID and severity, make the boto3 calls
      needed to evaluate it, and return a Finding for each violating resource.
"""

from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Severity

class NotReadableError(Exception):
    def __init__(self, value_name, reason):
        super().__init__(f"{value_name} is {reason}")
        self.value_name = value_name
        self.reason = reason
        

def _is_public_via_policy(bucket, account_bpa):
    if account_bpa["document"]["BlockPublicPolicy"] or account_bpa["document"]["RestrictPublicBuckets"]:
        return False
    if bucket["bucket_bpa"]["document"]["BlockPublicPolicy"] or bucket["bucket_bpa"]["document"]["RestrictPublicBuckets"]:
        return False
    if bucket["policy"]["status"] != "ok":
        raise NotReadableError("policy", bucket["policy"]["status"])
    if bucket["policy"]["document"] is None:
        return False
    for statement in bucket["policy"]["document"]["Statement"]:
        if statement["Effect"] == "Allow" and statement["Principal"] == "*":
            return True
    return False

class S3PublicAccess(BaseCheck):
    control_id = "3.1.4"
    title = "S3 Bucket Publicly Accessible"
    severity = Severity.CRITICAL
    remediable = True
    requires =  ["s3_buckets", "account_bpa"]

    def evaluate(self, snapshot):
        return CheckResult(CheckStatus.EVALUATED, [], self.control_id, None)
    