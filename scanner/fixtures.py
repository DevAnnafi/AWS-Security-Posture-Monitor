from copy import deepcopy

FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [
            {
                "name": "bucket-a",
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
                    "status": "ok",
                    "document": {
                        "Rules": [
                            {"ObjectOwnership": "BucketOwnerPreferred"}
                        ]
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
                        "Rules": [
                            {"ObjectOwnership": "BucketOwnerPreferred"}
                        ]
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
    },
}


ALLUSERS_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [
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
                    "document": None,
                },
                "acl": {
                    "status": "ok",
                    "document": {
                        "Owner": {
                            "DisplayName": "bucket-admin",
                            "ID": "bucket_2",
                        },
                        "Grants": [
                            {
                                "Grantee": {
                                    "Type": "Group",
                                    "URI": (
                                        "http://acs.amazonaws.com/"
                                        "groups/global/AllUsers"
                                    ),
                                },
                                "Permission": "FULL_CONTROL",
                            }
                        ],
                    },
                },
            }
        ],
    },
}


AUTHENTICATED_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [
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
                    "document": None,
                },
                "acl": {
                    "status": "ok",
                    "document": {
                        "Owner": {
                            "DisplayName": "bucket-admin",
                            "ID": "bucket_3",
                        },
                        "Grants": [
                            {
                                "Grantee": {
                                    "Type": "Group",
                                    "URI": (
                                        "http://acs.amazonaws.com/"
                                        "groups/global/"
                                        "AuthenticatedUsers"
                                    ),
                                },
                                "Permission": "FULL_CONTROL",
                            }
                        ],
                    },
                },
            }
        ],
    },
}


SECURITY_GROUP_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [],
    },

    "security_groups": {
        "status": "ok",
        "document": [
            {
                "region": "us-east-1",
                "status": "ok",
                "document": [
                    {
                        "GroupId": "sg-0123456789abcdef0",
                        "region": "us-east-1",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                            },
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 3389,
                                "ToPort": 3389,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                            },
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }
        ],
    },
}


ACCESS_DENIED_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [],
    },

    "security_groups": {
        "status": "access_denied",
        "document": [
            {
                "region": "us-east-1",
                "status": "access_denied",
                "document": None,
            }
        ],
    },
}


CLEAN_ENVIRONMENT_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [],
    },

    "iam_policies": {
        "status": "ok",
        "document": [],
    },

    "security_groups": {
        "status": "ok",
        "document": [
            {
                "region": "us-east-1",
                "status": "ok",
                "document": [],
            }
        ],
    },
}

S3_EVERYTHING_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "ok",
        "document": [
            {
                "name": "bucket-a",
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
                    "status": "ok",
                    "document": {
                        "Rules": [
                            {"ObjectOwnership": "BucketOwnerPreferred"}
                        ]
                    },
                },
                "policy": {
                    "status": "ok",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "s3:*",
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
        ],
    },
}

S3_NOTREADABLE_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "ok",
        "document": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    },

    "s3_buckets": {
        "status": "access_denied",
        "document": None           
    },
}

S3_ACCOUNT_BPA_NOTREADABLE_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "account_bpa": {
        "status": "access_denied",
        "document": None,
    },

    "s3_buckets": {
        "status": "ok",
        "document": [
            {
                "name": "bucket-a",
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
                    "status": "ok",
                    "document": {
                        "Rules": [
                            {"ObjectOwnership": "BucketOwnerPreferred"}
                        ]
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
            }
        ],
    },
}

IAM_WILDCARD_POLICY_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "iam_policies": {
        "status": "ok",
        "document": [
            {
                "name": "full-admin-policy",
                "arn": "arn:aws:iam::157182991517:policy/full-admin-policy",
                "attachment_count": 1,
                "document": {
                    "status": "ok",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        ],
    },
}


IAM_UNATTACHED_WILDCARD_POLICY_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "iam_policies": {
        "status": "ok",
        "document": [
            {
                "name": "unattached-full-admin-policy",
                "arn": (
                    "arn:aws:iam::157182991517:policy/"
                    "unattached-full-admin-policy"
                ),
                "attachment_count": 0,
                "document": {
                    "status": "ok",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        ],
    },
}

IAM_WILDCARD_POLICY_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "iam_policies": {
        "status": "ok",
        "document": [
            {
                "name": "full-admin-policy",
                "arn": "arn:aws:iam::157182991517:policy/full-admin-policy",
                "attachment_count": 1,
                "document": {
                    "status": "ok",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        ],
    },
}


IAM_UNATTACHED_WILDCARD_POLICY_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "iam_policies": {
        "status": "ok",
        "document": [
            {
                "name": "unattached-full-admin-policy",
                "arn": (
                    "arn:aws:iam::157182991517:policy/"
                    "unattached-full-admin-policy"
                ),
                "attachment_count": 0,
                "document": {
                    "status": "ok",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        ],
    },
}


IAM_SERVICE_WILDCARD_POLICY_FIXTURE = {
    "collection_window": None,
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],

    "iam_policies": {
        "status": "ok",
        "document": [
            {
                "name": "s3-wildcard-policy",
                "arn": "arn:aws:iam::157182991517:policy/s3-wildcard-policy",
                "attachment_count": 1,
                "document": {
                    "status": "ok",
                    "document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "*",
                            }
                        ],
                    },
                },
            }
        ],
    },
}

ACL_UNREADABLE_FIXTURE = deepcopy(ALLUSERS_FIXTURE)
ACL_UNREADABLE_FIXTURE["s3_buckets"]["document"][0]["acl"] = {
    "status": "access_denied",
    "document": None,
}


ACL_PARSE_ERROR_FIXTURE = deepcopy(ALLUSERS_FIXTURE)
ACL_PARSE_ERROR_FIXTURE["s3_buckets"]["document"][0]["acl"] = {
    "status": "parse_error",
    "document": None,
}


ACL_READ_ACP_FIXTURE = deepcopy(ALLUSERS_FIXTURE)
ACL_READ_ACP_FIXTURE["s3_buckets"]["document"][0]["acl"]["document"]["Grants"][0][
    "Permission"
] = "READ_ACP"

IAM_NOTREADABLE_FIXTURE = {
    "account_id": "157182991517",
    "regions_covered": ["us-east-1"],
    "iam_policies": {
        "status": "access_denied",
        "document": None,
    },
}