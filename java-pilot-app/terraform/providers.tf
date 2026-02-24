terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # INTENTIONALLY unpinned to let scanners/AI propose pinning
      # version = "~> 5.60"  # (target fix)
    }
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region (for demo/scans only)"
  default     = "us-east-1"
}

variable "project" {
  type        = string
  description = "Project name prefix (used in resource names)"
  default     = "bugbuster"
}

provider "aws" {
  region = var.aws_region
}