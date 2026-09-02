from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Severity
from enum import Enum
from typing import NamedTuple, Optional

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PERMISSION_ACL_CONTROLS = (
    "READ",
    "WRITE", 
    "WRITE_ACP", 
    "FULL_CONTROL"
)

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

class PublicExposure(Enum):
    NONE = (False, None)
    AUTHENTICATED_USERS = (True, Severity.HIGH)
    ALL_USERS = (True, Severity.CRITICAL)

    def __init__(self, is_public: bool, severity: Optional[str]):
        self.is_public = is_public
        self.severity = severity


def _is_public_via_acl(bucket, account_bpa):
    if account_bpa["document"]["BlockPublicAcls"] or account_bpa["document"]["IgnorePublicAcls"]:
        return PublicExposure.NONE
    if bucket["bucket_bpa"]["document"]["BlockPublicAcls"] or bucket["bucket_bpa"]["document"]["IgnorePublicAcls"]:
        return PublicExposure.NONE
    if bucket["ownership_controls"]["status"] != "ok":
        raise NotReadableError("ownership_controls", bucket["ownership_controls"]["status"])
    if bucket["ownership_controls"]["document"]["Rules"][0]["ObjectOwnership"] == "BucketOwnerEnforced":
        return PublicExposure.NONE
    if bucket["acl"]["status"] != "ok":
        raise NotReadableError("acl", bucket["acl"]["status"])
    if bucket["acl"]["document"] is None:
        return PublicExposure.NONE

    all_users_granted = False
    authenticated_users_granted = False

    for grant in bucket["acl"]["document"]["Grants"]:
        if grant["Grantee"]["Type"] != "Group":
            continue

        if (
            grant["Grantee"]["URI"] == ALL_USERS_URI and grant["Permission"] in PERMISSION_ACL_CONTROLS
        ):
            all_users_granted = True

        if (
            grant["Grantee"]["URI"] == AUTHENTICATED_USERS_URI and grant["Permission"] in PERMISSION_ACL_CONTROLS
        ):
            authenticated_users_granted = True

    if all_users_granted:
        return PublicExposure.ALL_USERS

    if authenticated_users_granted:
        return PublicExposure.AUTHENTICATED_USERS

    return PublicExposure.NONE
    
class S3PublicAccess(BaseCheck):
    control_id = "3.1.4"
    title = "S3 Bucket Publicly Accessible"
    severity = Severity.CRITICAL
    remediable = True
    requires =  ["s3_buckets", "account_bpa"]

    def evaluate(self, snapshot):
        return CheckResult(CheckStatus.EVALUATED, [], self.control_id, None)
    