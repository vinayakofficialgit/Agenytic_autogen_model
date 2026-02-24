# =======================================================
# SECURE BUCKET PATTERN (for RAG to learn & AI to replicate)
# Tag: ai: secure-pattern
# =======================================================

# A separate, hardened bucket showing best practices your AI should copy
resource "aws_s3_bucket" "secure_pattern" {
  bucket = "${var.project}-secure-pattern"
  acl    = "private"

  tags = {
    Purpose = "secure-pattern"
  }
}

# Block all forms of public access
resource "aws_s3_bucket_public_access_block" "secure_pattern" {
  bucket                  = aws_s3_bucket.secure_pattern.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning enabled
resource "aws_s3_bucket_versioning" "secure_pattern" {
  bucket = aws_s3_bucket.secure_pattern.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Default encryption (SSE-S3)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_pattern" {
  bucket = aws_s3_bucket.secure_pattern.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
      # kms_master_key_id = var.kms_key_id   # <- can be added later for SSE-KMS
    }
    bucket_key_enabled = true
  }
}

# (Optional) Least-privilege policy example - only your account can access
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "secure_lp" {
  statement {
    sid     = "RestrictToAccount"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["${aws_s3_bucket.secure_pattern.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "secure_lp" {
  bucket = aws_s3_bucket.secure_pattern.id
  policy = data.aws_iam_policy_document.secure_lp.json
}