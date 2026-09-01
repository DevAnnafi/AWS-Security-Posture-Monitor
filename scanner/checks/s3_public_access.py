"""CIS check: 2.1.5 - S3 bucket publicly accessible.

TODO: implement. Declare the control ID and severity, make the boto3 calls
      needed to evaluate it, and return a Finding for each violating resource.
"""

from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Severity

class S3PublicAccess(BaseCheck):
    control_id = "3.1.4"
    title = "S3 Bucket Publicly Accessible"
    severity = Severity.CRITICAL
    remediable = True
    requires =  ["s3_buckets", "account_bpa"]

    def evaluate(self, snapshot):
        return CheckResult(CheckStatus.EVALUATED, [], self.control_id, None)
    