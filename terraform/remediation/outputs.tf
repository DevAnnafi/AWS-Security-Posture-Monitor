output "lambda_function_name" {
  description = "Name of the remediation Lambda."
  value       = aws_lambda_function.remediation.function_name
}

output "lambda_function_arn" {
  description = "ARN of the remediation Lambda."
  value       = aws_lambda_function.remediation.arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role."
  value       = aws_iam_role.remediation_lambda.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge remediation rule."
  value       = aws_cloudwatch_event_rule.remediation.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge remediation rule."
  value       = aws_cloudwatch_event_rule.remediation.arn
}

output "sns_topic_arn" {
  description = "ARN of the remediation SNS topic."
  value       = aws_sns_topic.remediation.arn
}