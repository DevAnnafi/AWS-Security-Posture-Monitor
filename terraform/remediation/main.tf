terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = "terraform"
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  lambda_name = "${var.name_prefix}-lambda"

  remediation_role_name = "${var.name_prefix}-lambda-role"

  event_rule_name = "${var.name_prefix}-events"

  sns_topic_name = "${var.name_prefix}-notifications"

  # IAM role assumed by the remediation Lambda.
  remediation_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${local.remediation_role_name}"

  # CloudTrail represents Lambda's assumed-role session as:
  #
  # arn:aws:sts::<account-id>:assumed-role/<role-name>/<session-name>
  #
  # Only this specific role is excluded from EventBridge.
  remediation_assumed_role_prefix = "arn:${data.aws_partition.current.partition}:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${local.remediation_role_name}/"

  # Events that can create or expose the S3 public-access condition
  # checked by control 3.1.4.
  s3_events = [
    "PutBucketPublicAccessBlock",
    "DeletePublicAccessBlock",
    "PutBucketPolicy",
    "PutBucketAcl",
  ]

  # Event that can create the insecure inbound rule checked by
  # control 6.3.
  ec2_events = [
    "AuthorizeSecurityGroupIngress",
  ]
}

# ---------------------------------------------------------
# Lambda deployment package
#
# The Lambda imports both:
#
#   lambda_functions.*
#   scanner.*
#
# Therefore the project root must be packaged.
# ---------------------------------------------------------

data "archive_file" "remediation_lambda" {
  type = "zip"

  source_dir = abspath(var.project_root)

  output_path = "${path.module}/remediation_lambda.zip"

  excludes = [
    ".git",
    ".github",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "terraform",
    "dashboard",
    "docs",
    "api",
    "scanner/tests",
    "*.pyc",
  ]
}

# ---------------------------------------------------------
# Lambda
# ---------------------------------------------------------

resource "aws_lambda_function" "remediation" {
  function_name = local.lambda_name

  role = aws_iam_role.remediation_lambda.arn

  filename         = data.archive_file.remediation_lambda.output_path
  source_code_hash = data.archive_file.remediation_lambda.output_base64sha256

  runtime = var.lambda_runtime

  handler = "lambda_functions.handler.lambda_handler"

  timeout     = 60
  memory_size = 256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.remediation.arn
    }
  }

  # Make sure the execution policy exists before Lambda is created.
  depends_on = [
    aws_iam_role_policy.remediation_lambda
  ]
}

# ---------------------------------------------------------
# EventBridge
# ---------------------------------------------------------

resource "aws_cloudwatch_event_rule" "remediation" {
  name        = local.event_rule_name
  description = "Trigger CSPM remediation Lambda for relevant S3 and EC2 CloudTrail API calls."

  event_pattern = jsonencode({
    source = [
      "aws.s3",
      "aws.ec2"
    ]

    detail-type = [
      "AWS API Call via CloudTrail"
    ]

    detail = {
      eventSource = [
        "s3.amazonaws.com",
        "ec2.amazonaws.com"
      ]

      eventName = concat(
        local.s3_events,
        local.ec2_events
      )

      # -----------------------------------------------------
      # Loop guard
      #
      # Do NOT filter on:
      #
      #   userIdentity.type = AssumedRole
      #
      # because that would exclude every assumed role.
      #
      # Instead, exclude only the assumed-role sessions
      # belonging to this remediation Lambda.
      # -----------------------------------------------------

      userIdentity = {
        arn = [
          {
            "anything-but" = {
              "prefix" = local.remediation_assumed_role_prefix
            }
          }
        ]
      }
    }
  })
}

# ---------------------------------------------------------
# EventBridge -> Lambda
# ---------------------------------------------------------

resource "aws_cloudwatch_event_target" "remediation_lambda" {
  rule = aws_cloudwatch_event_rule.remediation.name

  arn = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id = "AllowEventBridgeInvoke"

  action = "lambda:InvokeFunction"

  function_name = aws_lambda_function.remediation.function_name

  principal = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.remediation.arn
}

# ---------------------------------------------------------
# SNS
# ---------------------------------------------------------

resource "aws_sns_topic" "remediation" {
  name = local.sns_topic_name
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.remediation.arn

  protocol = "email"

  endpoint = var.notification_email
}