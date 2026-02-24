# ============================
# INTENTIONALLY INSECURE BUCKET
# ============================

# 1) Publicly readable bucket (deterministic finding)
resource "aws_s3_bucket" "public_bucket" {
  bucket = "${var.project}-public-bucket-demo"
  acl    = "public-read"  # ❌ public

  # ❌ No versioning
  # ❌ No default encryption
  # ❌ No server access logging
  # (Left out intentionally for scanners/AI to fix)
}

# 2) Bucket policy allowing * to read objects (overly permissive)
data "aws_iam_policy_document" "public_read" {
  statement {
    sid     = "PublicReadGetObject"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "AWS"
      identifiers = ["*"]        # ❌ anyone
    }
    resources = ["${aws_s3_bucket.public_bucket.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "public_policy" {
  bucket = aws_s3_bucket.public_bucket.id
  policy = data.aws_iam_policy_document.public_read.json
}

# 3) (Missing) public access block — left out on purpose
# resource "aws_s3_bucket_public_access_block" "this" { ... }  # ✅ target fix

# 4) (Missing) default encryption — left out on purpose
# resource "aws_s3_bucket_server_side_encryption_configuration" "this" { ... }

# 5) (Missing) versioning — left out on purpose
# resource "aws_s3_bucket_versioning" "this" { ... }