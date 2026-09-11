resource "aws_iam_role" "remediation_lambda" {
  name = local.remediation_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "LambdaAssumeRole"
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "remediation_lambda" {
  name = "${var.name_prefix}-permissions"

  role = aws_iam_role.remediation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [

      # -----------------------------------------------------
      # S3 read permissions required for the re-scan.
      # -----------------------------------------------------

      {
        Sid    = "S3ReadForRescan"
        Effect = "Allow"

        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketOwnershipControls",
          "s3:GetPublicAccessBlock"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------
      # Account-level S3 BPA read.
      # -----------------------------------------------------

      {
        Sid    = "S3ControlReadForRescan"
        Effect = "Allow"

        Action = [
          "s3control:GetPublicAccessBlock"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------
      # S3 remediation.
      #
      # remediation.py calls only:
      #
      #   put_public_access_block
      # -----------------------------------------------------

      {
        Sid    = "S3Remediation"
        Effect = "Allow"

        Action = [
          "s3:PutBucketPublicAccessBlock"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------
      # EC2 read permission required for the re-scan.
      # -----------------------------------------------------

      {
        Sid    = "EC2ReadForRescan"
        Effect = "Allow"

        Action = [
          "ec2:DescribeSecurityGroups"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------
      # EC2 remediation.
      #
      # remediation.py calls only:
      #
      #   revoke_security_group_ingress
      # -----------------------------------------------------

      {
        Sid    = "EC2Remediation"
        Effect = "Allow"

        Action = [
          "ec2:RevokeSecurityGroupIngress"
        ]

        Resource = "*"
      },

      # -----------------------------------------------------
      # SNS notification.
      #
      # Lambda publishes only to the remediation topic.
      # -----------------------------------------------------

      {
        Sid    = "PublishRemediationNotifications"
        Effect = "Allow"

        Action = [
          "sns:Publish"
        ]

        Resource = aws_sns_topic.remediation.arn
      },

      # -----------------------------------------------------
      # CloudWatch Logs.
      # -----------------------------------------------------

      {
        Sid    = "LambdaLogging"
        Effect = "Allow"

        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]

        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}