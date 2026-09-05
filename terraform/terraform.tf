terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.92"
    }
  }

  required_version = ">= 1.2"
}

provider "aws" {
  region  = var.region
  profile = "terraform"

  default_tags {
    tags = {
      Project = "aws-security-posture-monitor"
    }
  }
}




