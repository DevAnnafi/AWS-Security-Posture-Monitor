variable "region" {
  type        = string
  description = "AWS region for all lab resources"
  default     = "us-east-1"
}

variable "name_prefix" {
  type        = string
  description = "AWS name for all resources"
  default     = "cspm-lab"
}
