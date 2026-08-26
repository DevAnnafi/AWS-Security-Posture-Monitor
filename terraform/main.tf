# Deliberately vulnerable lab environment.
#
# WARNING: creates internet-reachable insecure resources.
#          Sandbox accounts only. Always run terraform destroy when finished.

resource "aws_s3_bucket" "public" {
  bucket = "${var.name_prefix}-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.public.id

  depends_on = [
    aws_s3_bucket_public_access_block.public
  ]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public.arn}/*"
      }
    ]
  })
}

resource "aws_s3_object" "hello" {
  bucket  = aws_s3_bucket.public.id
  key     = "hello.txt"
  content = "hello from the cspm lab"
}

# Deviation: intentionally leaves server-side encryption
# unconfigured to test detection of an unencrypted S3 bucket.
resource "aws_s3_bucket" "unencrypted" {
  bucket = "${var.name_prefix}-unencrypted-bucket"
}

resource "aws_vpc" "lab" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "cspm-lab-vpc"
  }
}

resource "aws_security_group" "ssh_open" {
  name        = "cspm-lab-ssh-open"
  description = "Security group allowing SSH from anywhere"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = "aws-security-posture-monitor"
  }
}

resource "aws_iam_policy" "full_access" {
  name        = "${var.name_prefix}-full-access-test"
  description = "Deliberately overprivileged policy for security testing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "unassumable_role" {
  name = "${var.name_prefix}-unassumable-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"

        # Deliberately trusts EC2, but no instance profile is
        # created, so this role remains inert while its
        # overprivileged policy remains detectable.
        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "full_access_attachment" {
  role       = aws_iam_role.unassumable_role.name
  policy_arn = aws_iam_policy.full_access.arn
}

resource "aws_ebs_volume" "unencrypted_test" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = false

  tags = {
    Name = "${var.name_prefix}-unencrypted-test-volume"
  }
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.name_prefix}-cloudtrail-logs-test"
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-CloudTrail-Logs"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"

        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }

        Action = "s3:PutObject"

        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "single_region_test" {
  name                          = "${var.name_prefix}-single-region-test-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = false
  include_global_service_events = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs
  ]
}