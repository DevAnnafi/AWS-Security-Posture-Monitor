from scanner.models import Severity

READ_ONLY_LIST = ["s3:GetObject", "s3:ListBucket"]

CAPABILITY_TO_SEVERITY = {
    1 : Severity.MEDIUM,
    2 : Severity.HIGH,
    3 : Severity.CRITICAL
}

def capability_level(statement):
    action = statement["Action"]
    if isinstance(action, str):
        action = [action]    
    if all(a in READ_ONLY_LIST for a in action):
        return 1
    return 2

def acl_capability_level(grant):
    acl = grant["Permission"]
    if acl == "READ":
        return 1
    return 2
    




