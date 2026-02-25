import pathlib
import difflib
import re
from typing import List, Dict, Any


def query_for(item: dict) -> str:
    return "terraform s3 bucket public access block versioning encryption AES256"


def _read(p: str) -> str:
    data = pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")  # normalize EOL


def _write_diff(old: str, new: str, path: str) -> str:
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    diff = difflib.unified_diff(a, b, fromfile=path, tofile=path)
    return "".join(diff)


def try_deterministic(item: dict) -> str | None:
    path = item.get("file", "")
    if not path.endswith(".tf"):
        return None

    raw = _read(path)
    changed = raw

    # S3 bucket hardening additions (append if missing)
    if 'resource "aws_s3_bucket" "public_bucket"' in changed:
        if "aws_s3_bucket_public_access_block" not in changed:
            changed += """
resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
        if "aws_s3_bucket_versioning" not in changed:
            changed += """
resource "aws_s3_bucket_versioning" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""
        if "aws_s3_bucket_server_side_encryption_configuration" not in changed:
            changed += """
resource "aws_s3_bucket_server_side_encryption_configuration" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}
"""

    # Example SG hardening
    changed = re.sub(
        r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        'cidr_blocks = ["10.0.0.0/16"]',
        changed,
    )

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    return None