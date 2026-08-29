bucket_a = {
    "name": "bucket-a",
    "region": "us-east-1",
    "bucket_bpa": False,
    "policy": {
        "status": "ok",
        "document": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket-a/*",
                }
            ]
        }
    },

}

print(bucket_a)


bucket_b = {
    "name": "bucket-b",
    "region": "us-east-1",
    "bucket_bpa": False,
    "policy": {
        "status": "ok",
        "document": None,
    },
}

print(bucket_b)

bucket_c = {
    "name": "bucket-c",
    "region": "us-east-1",
    "bucket_bpa": False,
    "policy": {
        "status": "access_denied",
        "document": None,
    }
}

print((bucket_c))