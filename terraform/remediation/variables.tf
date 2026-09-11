variable "aws_region" {
  description = "AWS region where the remediation resources are deployed."
  type        = string
  default     = "us-east-1"
}

variable "project_root" {
  description = "Path from this Terraform directory to the project root."
  type        = string
  default     = "../.."
}

variable "lambda_runtime" {
  description = "Python runtime used by the remediation Lambda."
  type        = string
  default     = "python3.12"
}

variable "notification_email" {
  description = "Email address that receives remediation notifications."
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to remediation resources."
  type        = string
  default     = "aws-security-posture-remediation"
}