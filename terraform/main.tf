# Deliberately vulnerable lab environment.
#
# WARNING: creates internet-reachable insecure resources.
#          Sandbox accounts only. Always run terraform destroy when finished.
#
# TODO: public S3 bucket, unencrypted bucket, security group open on 22,
#       IAM policy with Action "*" / Resource "*", unencrypted EBS volume,
#       single-region CloudTrail.