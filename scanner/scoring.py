READ_ONLY_LIST = ["s3:GetObject", "s3:ListBucket"]

def capability_level(statement):
    action = statement["Action"]
    if isinstance(action, str):
        action = [action]    
    if all(a in READ_ONLY_LIST for a in action):
        return 1
    return 2

