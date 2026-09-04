from scanner.scoring import capability_level

def test_scoring():
    assert capability_level({"Action": "s3:GetObject"}) == 1
    assert capability_level({"Action": "s3:ListBucket"}) == 1
    assert capability_level({"Action" : "s3:PutObject"}) == 2
    assert capability_level({"Action" : "s3:SomeActionInventedNextYear"}) == 2
    assert capability_level({"Action": ["s3:GetObject"]}) == 1
    assert capability_level({"Action": ["s3:GetObject", "s3:PutObject"]}) == 2