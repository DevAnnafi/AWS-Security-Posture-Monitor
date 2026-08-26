# TODO: emit resource ARNs so the scanner's expected-findings fixture can
#       assert against them.

output "public_bucket_arn" {
  description = "Public Bucket Arn of the S3 bucket."
  value       = aws_s3_bucket.public.arn
}

output "unencrypted_bucket_arn" {
  description = "Unencrypted Bucket Arn of the S3 bucket"
  value       = aws_s3_bucket.unencrypted.arn
}

output "ssh_open_security_group_arn" {
  value = aws_security_group.ssh_open.arn
}

output "full_access_policy_arn" {
  value = aws_iam_policy.full_access.arn
}

output "unassumable_role_arn" {
  value = aws_iam_role.unassumable_role.arn
}

output "unencrypted_ebs_volume_arn" {
  value = aws_ebs_volume.unencrypted_test.arn
}

output "single_region_cloudtrail_arn" {
  value = aws_cloudtrail.single_region_test.arn
}

output "cloudtrail_log_bucket_arn" {
  value = aws_s3_bucket.cloudtrail_logs.arn
}