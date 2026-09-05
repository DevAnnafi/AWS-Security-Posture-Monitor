import boto3

def collect_buckets():
    client = boto3.client("s3")
    response = client.list_buckets()
    return response

print(collect_buckets())