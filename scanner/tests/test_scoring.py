from scanner.scoring import capability_level, acl_capability_level

def test_scoring():
    assert capability_level({"Action": "s3:GetObject"}) == 1
    assert capability_level({"Action": "s3:ListBucket"}) == 1
    assert capability_level({"Action" : "s3:PutObject"}) == 2
    assert capability_level({"Action" : "s3:SomeActionInventedNextYear"}) == 2
    assert capability_level({"Action": ["s3:GetObject"]}) == 1
    assert capability_level({"Action": ["s3:GetObject", "s3:PutObject"]}) == 2

def test_acl_scoring():
    assert acl_capability_level({"Permission" : "READ"}) == 1
    assert acl_capability_level({"Permission" : "FULL_CONTROL"}) == 2