#!/usr/bin/env python3
import pathlib
import re
from typing import List, Dict, Any


# ============================================================
# Query Builder
# ============================================================

def query_for(item: dict) -> str:
    return "terraform s3 bucket public access block versioning encryption AES256"


# ============================================================
# Helpers
# ============================================================

# def _resolve_full_path(path: str) -> str:
#     # normalize: remove leading slash so absolute paths become relative
#     normalized = path.lstrip("/")
#     p = pathlib.Path(normalized)
#     if p.exists():
#         return str(p)
#     prefixed = pathlib.Path("java-pilot-app") / p
#     if prefixed.exists():
#         return str(prefixed)
#     return ""


import os
import pathlib
from typing import Optional

REPO_ROOT = pathlib.Path(os.getenv("GITHUB_WORKSPACE", ".")).resolve()

def _resolve_full_path(path: str) -> Optional[str]:
    """
    Resolve incoming path into a file inside the repository.
    Returns absolute string path if found, else None.
    """
    if not path:
        return None

    # Normalize: drop leading slash and collapse redundant slashes
    normalized = pathlib.Path(path.lstrip("/"))

    # Candidate 1: repo root / normalized (e.g., repo/s3_insecure.tf)
    cand1 = (REPO_ROOT / normalized).resolve()
    try:
        cand1.relative_to(REPO_ROOT)
    except Exception:
        cand1 = None

    if cand1 and cand1.exists():
        return str(cand1)

    # Candidate 2: repo root / java-pilot-app / terraform / <name>
    cand2 = (REPO_ROOT / "java-pilot-app" / "terraform" / normalized.name).resolve()
    try:
        cand2.relative_to(REPO_ROOT)
    except Exception:
        cand2 = None

    if cand2 and cand2.exists():
        return str(cand2)

    # Candidate 3: repo root / terraform / <name>
    cand3 = (REPO_ROOT / "terraform" / normalized.name).resolve()
    try:
        cand3.relative_to(REPO_ROOT)
    except Exception:
        cand3 = None

    if cand3 and cand3.exists():
        return str(cand3)

    return None




def _read(path: str) -> str:
    p = pathlib.Path(path)
    if not p.exists():
        return ""
    data = p.read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")


# ============================================================
# Deterministic Terraform Hardening
# ============================================================

def try_deterministic(item: dict) -> Dict[str, str] | None:
    raw_path = item.get("file", "")
    if not raw_path.endswith(".tf"):
        return None

    path = _resolve_full_path(raw_path)
    if not path:
        print(f"⚠ Terraform file not found: {raw_path}")
        return None

    original = _read(path)
    if not original:
        return None

    modified = original

    # ========================================================
    # S3 Hardening
    # ========================================================

    if 'resource "aws_s3_bucket" "public_bucket"' in modified:

        if "aws_s3_bucket_public_access_block" not in modified:
            modified += """

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""

        if "aws_s3_bucket_versioning" not in modified:
            modified += """

resource "aws_s3_bucket_versioning" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""

        if "aws_s3_bucket_server_side_encryption_configuration" not in modified:
            modified += """

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

    # ========================================================
    # Security Group Hardening
    # ========================================================

    modified = re.sub(
        r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        'cidr_blocks = ["10.0.0.0/16"]',
        modified,
    )

    if modified == original:
        return None

    return {
        "file": path,
        "content": modified
    }


# ============================================================
# RAG fallback (disabled)
# ============================================================

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
    return None