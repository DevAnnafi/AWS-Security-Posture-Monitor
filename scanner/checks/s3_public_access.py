from scanner.registry import BaseCheck, CheckResult, CheckStatus
from scanner.models import Finding
from scanner.scoring import capability_level, CAPABILITY_TO_SEVERITY, acl_capability_level
from enum import Enum


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
        return False, None
    if bucket["bucket_bpa"]["document"]["BlockPublicPolicy"] or bucket["bucket_bpa"]["document"]["RestrictPublicBuckets"]:
        return False, None
    if bucket["policy"]["status"] != "ok":
        raise NotReadableError("policy", bucket["policy"]["status"])
    if bucket["policy"]["document"] is None:
        return False, None
    for statement in bucket["policy"]["document"]["Statement"]:
        if statement["Effect"] == "Allow" and statement["Principal"] == "*":
            return True, statement
    return False, None

class PublicExposure(Enum):
    NONE = "none"
    AUTHENTICATED_USERS = "authenticated_users"
    ALL_USERS = "all_users"


def _is_public_via_acl(bucket, account_bpa):
    if account_bpa["document"]["BlockPublicAcls"] or account_bpa["document"]["IgnorePublicAcls"]:
        return PublicExposure.NONE, None
    if bucket["bucket_bpa"]["document"]["BlockPublicAcls"] or bucket["bucket_bpa"]["document"]["IgnorePublicAcls"]:
        return PublicExposure.NONE, None
    if bucket["ownership_controls"]["status"] != "ok":
        raise NotReadableError("ownership_controls", bucket["ownership_controls"]["status"])
    if bucket["ownership_controls"]["document"]["Rules"][0]["ObjectOwnership"] == "BucketOwnerEnforced":
        return PublicExposure.NONE, None
    if bucket["acl"]["status"] != "ok":
        raise NotReadableError("acl", bucket["acl"]["status"])
    if bucket["acl"]["document"] is None:
        return PublicExposure.NONE, None

    all_users_grant = None
    authenticated_users_grant = None

    for grant in bucket["acl"]["document"]["Grants"]:
        if grant["Grantee"]["Type"] != "Group":
            continue

        if (
            grant["Grantee"]["URI"] == ALL_USERS_URI and grant["Permission"] in PERMISSION_ACL_CONTROLS
        ):
            all_users_grant = grant

        if (
            grant["Grantee"]["URI"] == AUTHENTICATED_USERS_URI and grant["Permission"] in PERMISSION_ACL_CONTROLS
        ):
            authenticated_users_grant = grant

    if all_users_grant:
        return PublicExposure.ALL_USERS, all_users_grant

    if authenticated_users_grant:
        return PublicExposure.AUTHENTICATED_USERS, authenticated_users_grant

    return PublicExposure.NONE, None
    
class S3PublicAccess(BaseCheck):
    control_id = "3.1.4"
    title = "S3 Bucket Publicly Accessible"
    remediable = True
    requires =  ["s3_buckets", "account_bpa"]

    def evaluate(self, snapshot):
        if snapshot["s3_buckets"]["status"] != "ok":
            return CheckResult(
                status=CheckStatus.CANT_EVALUATE,
                findings=[],
                control_id=self.control_id,
                error=snapshot["s3_buckets"]["status"],
                unevaluated=[],
            )
        buckets = snapshot["s3_buckets"]["document"]
        account_bpa = snapshot["account_bpa"]
        unevaluated_list = []
        findings_list = []
        account_id = snapshot["account_id"]
        for bucket in buckets:
           resource_id = f"arn:aws:s3:::{bucket['name']}"
           try:
                acl_exposure, acl_grant = _is_public_via_acl(bucket, account_bpa)
                policy_public, statement = _is_public_via_policy(bucket, account_bpa)
           except NotReadableError as e:
               unevaluated_list.append({"resource_id": f"arn:aws:s3:::{bucket['name']}", "reason": e.reason})
               continue
          
           if policy_public is True:
                findings_list.append(Finding(
                    control_id=self.control_id,
                    title=self.title,
                    severity=CAPABILITY_TO_SEVERITY[capability_level(statement)],
                    resource_id=resource_id,
                    resource_sub_id="policy",
                    region=bucket["region"],
                    remediable=self.remediable,
                    evidence=bucket["policy"]["document"],
                    account_id=account_id
                ))
           if acl_exposure != PublicExposure.NONE:
               findings_list.append(Finding(
                    control_id=self.control_id,
                    title=self.title,
                    severity=CAPABILITY_TO_SEVERITY[acl_capability_level(acl_grant)],
                    resource_id=f"arn:aws:s3:::{bucket['name']}",
                    resource_sub_id="acl",
                    region=bucket["region"],
                    remediable=self.remediable,
                    evidence=bucket["acl"]["document"],
                    account_id=account_id
                ))

        if unevaluated_list:
            status = CheckStatus.PARTIAL
        elif findings_list:
            status = CheckStatus.VIOLATIONS
        else:
            status = CheckStatus.EVALUATED

        return CheckResult(
            status=status,
            findings=findings_list,
            control_id=self.control_id,
            error=None,
            unevaluated=unevaluated_list,
        )

               



               

               



    