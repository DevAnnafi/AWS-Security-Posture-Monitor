from enum import Enum
from botocore.exceptions import ClientError
import boto3
import json

class CollectionStatus(Enum):
    OK = "ok"
    ACCESS_DENIED = "access_denied"
    PARSE_ERROR = "parse_error"

def collect_buckets():
    client = boto3.client("s3")
    response = client.list_buckets()
    return response

def collect_policy(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        document = json.loads(response["Policy"])
        return {"status": CollectionStatus.OK.value, "document": document}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchBucketPolicy":
            return {"status": CollectionStatus.OK.value, "document": None}

        if error_code == "AccessDenied":
            return {"status": CollectionStatus.ACCESS_DENIED.value, "document": None}

        raise

    except json.JSONDecodeError:
        return {"status": CollectionStatus.PARSE_ERROR.value, "document": None}