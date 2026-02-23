from __future__ import annotations

import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any

from agents.ast_java_engine import ASTJavaEngine


# =============================
# Utilities
# =============================
def _is_autofix_severity(sev):
    return str(sev or "").lower() in ["high", "critical", "error"]


def _sanitize_diff(diff: str) -> str:
    if not diff:
        return diff
    diff = diff.replace("```diff", "").replace("```", "").strip()
    return diff


def _parse_diff_changed_files(diff: str) -> List[str]:
    files = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            files.append(line.replace("+++ b/", "").strip())
    return list(set(files))


def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
    repo_root = repo_root.resolve()
    for f in files:
        p = (repo_root / f).resolve()
        if not str(p).startswith(str(repo_root)):
            return False
    return True


def _git_apply_patch(repo: Path, diff: str) -> bool:
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "-"],
            cwd=repo,
            input=diff.encode(),
        )
        if proc.returncode != 0:
            return False

        proc = subprocess.run(
            ["git", "apply", "-"],
            cwd=repo,
            input=diff.encode(),
        )
        return proc.returncode == 0

    except Exception as e:
        print("[fixer] patch error:", e)
        return False


# =========================================================
# FIXER CLASS
# =========================================================
class Fixer:
    def __init__(self, cfg, output_dir, repo_root=Path(".")):
        self.cfg = cfg or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root)
        self.ast_engine = ASTJavaEngine(repo_root=self.repo, debug=False)

    # -------------------------------------------------
    def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
        notes, changed = [], []

        dockerfile = self.repo / "Dockerfile"
        if dockerfile.exists():
            text = dockerfile.read_text()
            if "USER root" in text:
                dockerfile.write_text(text.replace("USER root", "USER appuser"))
                notes.append("[deterministic] Dockerfile hardened")
                changed.append("Dockerfile")

        return notes, changed

    # -------------------------------------------------
    def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
        prompt = f"You MUST output ONLY unified git diff patch.\nFix vulnerability:\n{item}"

        try:
            from agents.llm_bridge import assistant_factory
            diff = assistant_factory().generate_patch(prompt)
            diff = _sanitize_diff(diff)
            return diff, False

        except Exception as e:
            print("[fixer] LLM error:", e)
            return "", True

    # -------------------------------------------------
    def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
        notes, changed_files = [], []

        for tool, items in grouped.items():
            for item in items:

                if not _is_autofix_severity(item.get("severity")):
                    continue

                file_path = item.get("file") or item.get("path") or ""
                title = str(item.get("title", "")).lower()

                print(f"[fixer] vulnerability in: {file_path} -> {item.get('title')}")

                # Only Java handled by AST
                if not file_path.endswith(".java"):
                    notes.append(f"[fixer] AST skipped (non-java finding): {item.get('title')}")
                    continue

                diff, fallback = self._llm_propose_patch_for_item(item)

                # ======================================================
                # LLM invalid → AST structural fallback
                # ======================================================
                if fallback or not diff or "--- a/" not in diff:

                    notes.append(f"[fixer] LLM patch invalid → AST fallback: {item.get('title')}")

                    # Normalize title for classifier
                    if "sql" in title:
                        item["title"] = "SQL injection"
                    elif "command" in title or "exec" in title:
                        item["title"] = "command injection"

                    ast_result = self.ast_engine.apply_for_finding(item)

                    notes.extend(ast_result.notes)
                    changed_files.extend(ast_result.changed_files)

                    # Compile validation after AST change
                    if ast_result.ok and ast_result.changed_files:
                        ok, msg = self.ast_engine.compile_validate()
                        notes.append(msg)

                        if not ok:
                            notes.append("[fixer] compile failed after AST fix")

                    continue

                # ======================================================
                # LLM patch apply path
                # ======================================================
                targets = _parse_diff_changed_files(diff)
                targets = [t.replace("a/", "").replace("b/", "") for t in targets]

                if not _patch_targets_repo(self.repo, targets):
                    notes.append("[fixer] patch rejected outside repo")
                    continue

                if _git_apply_patch(self.repo, diff):
                    notes.append("[fixer] LLM patch applied")
                    changed_files.extend(targets)
                else:
                    notes.append("[fixer] LLM patch failed → AST fallback")

                    ast_result = self.ast_engine.apply_for_finding(item)
                    notes.extend(ast_result.notes)
                    changed_files.extend(ast_result.changed_files)

                    if ast_result.ok and ast_result.changed_files:
                        ok, msg = self.ast_engine.compile_validate()
                        notes.append(msg)

                        if not ok:
                            notes.append("[fixer] compile failed after AST fix")

        return notes, list(set(changed_files))

    # # -------------------------------------------------
    # def apply(self, grouped):
    #     notes, changed = [], []

    #     n1, c1 = self._apply_deterministic_fixes()
    #     notes += n1
    #     changed += c1

    #     n2, c2 = self._apply_llm_autofixes(grouped)
    #     notes += n2
    #     changed += c2

    #     changed = list(set(changed))

    #     self.out.mkdir(parents=True, exist_ok=True)

    #     (self.out / "patch_manifest.json").write_text(
    #         json.dumps({"files": changed, "notes": notes}, indent=2)
    #     )

    #     print("[fixer] changed files:", changed)
    #     return notes, changed


    # --- inside class Fixer, add this method ---
    def _apply_iac_s3_fixes(self, tf_root: Path):
        """
        Deterministic Terraform fixes for S3 buckets flagged by tfsec:
          - AVD-AWS-0092: public ACL -> private
          - AVD-AWS-0088/0132: add SSE (uses KMS if S3_KMS_KEY_ARN env provided; else SSE-S3)
          - AVD-AWS-0086/87/91/93/0094: add aws_s3_bucket_public_access_block with all four booleans true
        """
        notes, changed = [], []
        if not tf_root.exists():
            return notes, changed
    
        kms_arn = os.getenv("S3_KMS_KEY_ARN", "").strip()
    
        # 1) In-place update for bucket resources across *.tf
        for tf in tf_root.rglob("*.tf"):
            text = tf.read_text(encoding="utf-8")
            original = text
    
            # (a) Prevent public ACLs
            text = re.sub(r'acl\s*=\s*"public-read(-write)?"', 'acl = "private"', text)
    
            # (b) Ensure SSE block (prefer KMS if provided; else SSE-S3)
            def add_sse_block(match):
                block = match.group(0)
                if "server_side_encryption_configuration" in block:
                    return block  # already present
                if kms_arn:
                    sse = f'''
      server_side_encryption_configuration {{
        rule {{
          apply_server_side_encryption_by_default {{
            sse_algorithm     = "aws:kms"
            kms_master_key_id = "{kms_arn}"
          }}
        }}
      }}'''
                else:
                    sse = '''
      server_side_encryption_configuration {
        rule {
          apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
          }
        }
      }'''
                return re.sub(r'\}\s*$', f'{sse}\n}}', block, flags=re.S)
    
            # inject SSE into each aws_s3_bucket resource
            text = re.sub(
                r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[\s\S]*?\}',
                add_sse_block,
                text,
                flags=re.S
            )
    
            if text != original:
                tf.write_text(text, encoding="utf-8")
                notes.append(f"[iac] updated {tf}")
                changed.append(str(tf.relative_to(self.repo)))
    
        # 2) Ensure Public Access Block is present (one per bucket)
        pab_tf = tf_root / "s3_public_access_block.tf"
        required = []
        for tf in tf_root.rglob("*.tf"):
            if tf == pab_tf:
                continue
            src = tf.read_text(encoding="utf-8")
            required += re.findall(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', src)
        required = sorted(set(required))
    
        want_body = ""
        for name in required:
            want_body += f'''
    resource "aws_s3_bucket_public_access_block" "{name}_pab" {{
      bucket = aws_s3_bucket.{name}.id
    
      block_public_acls       = true
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true
    }}
    '''.strip() + "\n\n"
    
        if required:
            current = pab_tf.read_text(encoding="utf-8") if pab_tf.exists() else ""
            if current.strip() != want_body.strip():
                pab_tf.write_text(want_body.strip() + "\n", encoding="utf-8")
                notes.append(f"[iac] wrote {pab_tf.relative_to(self.repo)} for: {', '.join(required)}")
                changed.append(str(pab_tf.relative_to(self.repo)))
    
        return notes, list(set(changed))

    # --- in apply(self, grouped) insert this call (keep your existing order) ---
    def apply(self, grouped):
        notes, changed = [], []
    
        n1, c1 = self._apply_deterministic_fixes()
        notes += n1; changed += c1
    
        # IaC S3 fixes
        tf_root = (self.repo / "hackathon-vuln-app" / "terraform")
        n_iac, c_iac = self._apply_iac_s3_fixes(tf_root)
        notes += n_iac; changed += c_iac
    
        n2, c2 = self._apply_llm_autofixes(grouped)
        notes += n2; changed += c2
    
        changed = list(set(changed))
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "patch_manifest.json").write_text(
            json.dumps({"files": changed, "notes": notes}, indent=2), encoding="utf-8"
        )
        print("[fixer] changed files:", changed)
        return notes, changed