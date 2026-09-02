FIXTURE = {
    "collection_window": None,
    "account_id":"157182991517",
    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },
    "s3_buckets": [
        {
            "name": "bucket-a",
            "region": "us-east-1",
            "bucket_bpa": 
            {
                "status": "ok",
                "document": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            },
            "ownership_controls": {
                "status": "ok",
                "document": {
                    "Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]
                },
            },
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
                },
            },
            "acl": {
                "status": "ok",
                "document": {
                    "Owner": {
                        "ID": "bucket_1",
                        "DisplayName": "bucket-owner-admin",
                    },
                    "Grants": [
                        {
                            "Grantee": {
                                "ID": "owner-user-id-12345",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "FULL_CONTROL",
                        },
                        {
                            "Grantee": {
                                "ID": "external-user-id-67890",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "READ",
                        },
                    ],
                },
            },
        },
        {
            "name": "bucket-b",
            "region": "us-east-1",
            "bucket_bpa": {
                "status": "ok",
                "document": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            },
            "ownership_controls": {
                "status": "ok",
                "document": {
                    "Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]
                },
            },
            "policy": {
                "status": "ok",
                "document": None,
            },
            "acl": {
                "status": "ok",
                "document": {
                    "Owner": {
                        "ID": "bucket_1",
                        "DisplayName": "bucket-owner-admin",
                    },
                    "Grants": [
                        {
                            "Grantee": {
                                "ID": "owner-user-id-12345",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "FULL_CONTROL",
                        }
                    ],
                },
            },
        },
        {
            "name": "bucket-c",
            "region": "us-east-1",
            "bucket_bpa": {
                "status": "ok",
                "document": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            },
            "ownership_controls": {
                "status": "access_denied",
                "document": None,
            },
            "policy": {
                "status": "access_denied",
                "document": None,
            },
            "acl": {
                "status": "access_denied",
                "document": None,
            },
        },
    ],
}

ALLUSERS_FIXTURE = {
    "account_id":"157182991517",
    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },
    "s3_buckets": [
        {
            "name": "acl-public-bucket",
            "region": "us-east-1",
            "bucket_bpa": {
                "status": "ok",
                "document": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            },
            "ownership_controls": {
                "status": "ok",
                "document": {
                    "Rules": [
                        {
                            "ObjectOwnership": "BucketOwnerPreferred"
                        }
                    ]
                },
            },
            "policy": {
                "status": "ok",
                "document": None
            },
            "acl": {
                "status": "ok",
                "document": {
                    "Owner": {
                        "DisplayName": "bucket-admin",
                        "ID": "bucket_2"
                    },
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            },
                            "Permission": "FULL_CONTROL",
                        }
                    ],
                },
            },
        }
    ],
}

AUTHENTICATED_FIXTURE = {
    "account_id":"157182991517",
    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },
    "s3_buckets": [
        {
            "name": "acl-public-bucket",
            "region": "us-east-1",
            "bucket_bpa": {
                "status": "ok",
                "document": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            },
            "ownership_controls": {
                "status": "ok",
                "document": {
                    "Rules": [
                        {
                            "ObjectOwnership": "BucketOwnerPreferred"
                        }
                    ]
                },
            },
            "policy": {
                "status": "ok",
                "document": None
            },
            "acl": {
                "status": "ok",
                "document": {
                    "Owner": {
                        "DisplayName": "bucket-admin",
                        "ID": "bucket_3"
                    },
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                            },
                            "Permission": "FULL_CONTROL",
                        }
                    ],
                },
            },
        }
    ],
}