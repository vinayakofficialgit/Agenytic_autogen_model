from pathlib import Path
from typing import Dict, Any, List, Tuple


class TerraformHclEngine:

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)

    def apply_for_finding(self, item: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        notes = []
        changed = []

        file_path = item.get("file") or item.get("path")
        if not file_path:
            return notes, changed

        target = self.repo_root / file_path
        if not target.exists():
            return notes, changed

        content = target.read_text()

        modified = False

        # Example fix: public S3 bucket hardening
        if "aws_s3_bucket" in content:
            if "acl" not in content:
                content += '\n  acl = "private"\n'
                modified = True

            if "block_public_acls" not in content:
                content += """
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
"""
                modified = True

        if modified:
            target.write_text(content)
            notes.append("[terraform] S3 public access hardened")
            changed.append(file_path)

        return notes, changed