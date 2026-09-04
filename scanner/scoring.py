READ_ONLY_LIST = ["s3:GetObject", "s3:ListBucket"]

def capability_level(statement):
    action = statement["Action"]
    if isinstance(action, str):
        action = [action]    
    if action in READ_ONLY_LIST:
        return 1
    return 2

