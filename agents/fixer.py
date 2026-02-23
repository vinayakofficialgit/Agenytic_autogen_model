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
# ✅ NEW: Read source file for LLM context
# =========================================================
def _read_source_file(repo: Path, file_path: str) -> str:
    """Read the actual source file so the LLM can generate an accurate diff."""
    try:
        full = repo / file_path
        if full.exists():
            return full.read_text(encoding="utf-8")
    except Exception:
        pass
    return ""


# =========================================================
# FIXER CLASS
# =========================================================
class Fixer:
    def __init__(self, cfg, output_dir, repo_root=Path(".")):
        self.cfg = cfg or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root)

        # Toggle AST fallback via env; default True for local runs
        self.ast_enabled = str(os.getenv("AST_ENABLED", "true")).lower() in ("1", "true", "yes")

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

        tf_root = (self.repo / "hackathon-vuln-app" / "terraform")
        if tf_root.exists():
            n_iac, c_iac = self._apply_iac_s3_fixes(tf_root)
            notes += n_iac
            changed += c_iac

        return notes, changed

    # =========================================================
    # ✅ FIX: Completely rewritten _llm_propose_patch_for_item
    # 
    # Problems fixed:
    #   1. assistant_factory() was called with NO args → TypeError
    #   2. .generate_patch() didn't exist → AttributeError
    #   3. Prompt didn't include actual source code → bad patches
    #   4. No file-path context → LLM couldn't produce valid diff
    # =========================================================
    def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
        file_path = item.get("file") or item.get("path") or ""
        source_code = _read_source_file(self.repo, file_path)
        
        rule_id = item.get("id") or item.get("rule_id") or item.get("check_id") or ""
        severity = item.get("severity", "")
        title = item.get("title") or item.get("message") or ""
        line = item.get("line", "")

        prompt = (
            "You MUST output ONLY a valid unified git diff patch. "
            "No explanations, no markdown fences, no commentary.\n\n"
            f"Vulnerability: {title}\n"
            f"Rule ID: {rule_id}\n"
            f"Severity: {severity}\n"
            f"File: {file_path}\n"
            f"Line: {line}\n\n"
        )

        if source_code:
            prompt += (
                f"Current source code of {file_path}:\n"
                "```\n"
                f"{source_code}\n"
                "```\n\n"
            )

        prompt += (
            "Generate a unified diff (--- a/... +++ b/...) that fixes this vulnerability.\n"
            "For SQL injection: use PreparedStatement with parameterized queries.\n"
            "For command injection: use ProcessBuilder with argument lists.\n"
            "Preserve all existing functionality. Only change what is necessary."
        )

        try:
            from agents.llm_bridge import assistant_factory

            agent = assistant_factory(
                name="patch_generator",
                system_message=(
                    "You are a senior security engineer. "
                    "Output ONLY valid unified diff patches. "
                    "No markdown code fences. No explanations. Just the diff."
                ),
                temperature=0.2,
            )
            diff = agent.generate_patch(prompt)
            diff = _sanitize_diff(diff)

            # Validate it looks like a real diff
            if diff and ("--- a/" in diff or "--- a\\" in diff):
                return diff, False
            else:
                print(f"[fixer] LLM returned non-diff output for {file_path}")
                return diff, True

        except Exception as e:
            print(f"[fixer] LLM error for {file_path}: {e}")
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

                # Only Java handled by LLM + AST; non-Java handled elsewhere
                if not file_path.endswith(".java"):
                    notes.append(f"[fixer] skipped (non-java finding): {item.get('title')}")
                    continue

                diff, fallback = self._llm_propose_patch_for_item(item)

                # ======================================================
                # LLM invalid → AST structural fallback (optional)
                # ======================================================
                if fallback or not diff or "--- a/" not in diff:

                    if not self.ast_enabled:
                        notes.append(f"[fixer] AST disabled; skipping fallback for: {item.get('title')}")
                        continue

                    notes.append(f"[fixer] LLM patch invalid → AST fallback: {item.get('title')}")

                    # ✅ FIX: Normalize title for AST classifier
                    # Semgrep rule "formatted-sql-string" needs to map to "SQL injection"
                    normalized_title = self._normalize_title_for_ast(title, item)
                    item_copy = dict(item)
                    item_copy["title"] = normalized_title

                    ast_result = self.ast_engine.apply_for_finding(item_copy)
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
                    notes.append(f"[fixer] LLM patch applied for {file_path}")
                    changed_files.extend(targets)
                else:
                    # LLM patch failed to apply
                    if not self.ast_enabled:
                        notes.append("[fixer] LLM patch failed and AST disabled; skipping fallback")
                        continue

                    notes.append("[fixer] LLM patch failed → AST fallback")

                    normalized_title = self._normalize_title_for_ast(title, item)
                    item_copy = dict(item)
                    item_copy["title"] = normalized_title

                    ast_result = self.ast_engine.apply_for_finding(item_copy)
                    notes.extend(ast_result.notes)
                    changed_files.extend(ast_result.changed_files)

                    if ast_result.ok and ast_result.changed_files:
                        ok, msg = self.ast_engine.compile_validate()
                        notes.append(msg)
                        if not ok:
                            notes.append("[fixer] compile failed after AST fix")

        return notes, list(set(changed_files))

    # =========================================================
    # ✅ NEW: Normalize finding title for AST classifier
    # Maps Semgrep rule IDs / titles to canonical vulnerability names
    # =========================================================
    def _normalize_title_for_ast(self, title: str, item: dict) -> str:
        """Map scanner-specific rule names to canonical vulnerability titles."""
        t = title.lower()
        rule_id = str(item.get("id") or item.get("rule_id") or "").lower()

        # SQL injection patterns
        sql_patterns = [
            "sql", "formatted-sql", "sql-string", "sqli",
            "jdbc", "createstatement", "executequery",
            "hibernate-sqli", "jpa-sqli",
        ]
        if any(p in t for p in sql_patterns) or any(p in rule_id for p in sql_patterns):
            return "SQL injection"

        # Command injection patterns
        cmd_patterns = ["command", "cmd-inject", "exec", "runtime.exec", "processbuilder"]
        if any(p in t for p in cmd_patterns) or any(p in rule_id for p in cmd_patterns):
            return "command injection"

        # Path traversal
        if "path" in t and "travers" in t:
            return "path traversal"

        # XSS
        if "xss" in t or "cross-site" in t:
            return "XSS"

        # SSRF
        if "ssrf" in t:
            return "SSRF"

        return title

    # -------------------------------------------------
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

    # --- Terraform S3 fixes ---
    def _apply_iac_s3_fixes(self, tf_root: Path):
        """
        Deterministic Terraform fixes for S3 buckets flagged by tfsec:
          - AVD-AWS-0092: public ACL -> private
          - AVD-AWS-0088/0132: add SSE
          - AVD-AWS-0086/87/91/93/0094: add aws_s3_bucket_public_access_block
        """
        notes, changed = [], []
        if not tf_root.exists():
            return notes, changed

        kms_arn = os.getenv("S3_KMS_KEY_ARN", "").strip()

        for tf in tf_root.rglob("*.tf"):
            text = tf.read_text(encoding="utf-8")
            original = text

            # Prevent public ACLs
            text = re.sub(r'acl\s*=\s*"public-read(-write)?"', 'acl = "private"', text)

            # Ensure SSE block
            def add_sse_block(match):
                block = match.group(0)
                if "server_side_encryption_configuration" in block:
                    return block
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

        # Public Access Block
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




# from __future__ import annotations

# import os
# import re
# import json
# import subprocess
# from pathlib import Path
# from typing import Dict, List, Tuple, Any

# from agents.ast_java_engine import ASTJavaEngine


# # =============================
# # Utilities
# # =============================
# def _is_autofix_severity(sev):
#     return str(sev or "").lower() in ["high", "critical", "error"]


# def _sanitize_diff(diff: str) -> str:
#     if not diff:
#         return diff
#     diff = diff.replace("```diff", "").replace("```", "").strip()
#     return diff


# def _parse_diff_changed_files(diff: str) -> List[str]:
#     files = []
#     for line in diff.splitlines():
#         if line.startswith("+++ b/"):
#             files.append(line.replace("+++ b/", "").strip())
#     return list(set(files))


# def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
#     repo_root = repo_root.resolve()
#     for f in files:
#         p = (repo_root / f).resolve()
#         if not str(p).startswith(str(repo_root)):
#             return False
#     return True


# def _git_apply_patch(repo: Path, diff: str) -> bool:
#     try:
#         proc = subprocess.run(
#             ["git", "apply", "--check", "-"],
#             cwd=repo,
#             input=diff.encode(),
#         )
#         if proc.returncode != 0:
#             return False

#         proc = subprocess.run(
#             ["git", "apply", "-"],
#             cwd=repo,
#             input=diff.encode(),
#         )
#         return proc.returncode == 0

#     except Exception as e:
#         print("[fixer] patch error:", e)
#         return False


# # =========================================================
# # FIXER CLASS
# # =========================================================
# class Fixer:
#     def __init__(self, cfg, output_dir, repo_root=Path(".")):
#         self.cfg = cfg or {}
#         self.out = Path(output_dir)
#         self.repo = Path(repo_root)

#         # ✅ NEW: toggle AST fallback via env; default True for local runs
#         self.ast_enabled = str(os.getenv("AST_ENABLED", "true")).lower() in ("1", "true", "yes")

#         self.ast_engine = ASTJavaEngine(repo_root=self.repo, debug=False)

#     # -------------------------------------------------
#     def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
#         notes, changed = [], []

#         dockerfile = self.repo / "Dockerfile"
#         if dockerfile.exists():
#             text = dockerfile.read_text()
#             if "USER root" in text:
#                 dockerfile.write_text(text.replace("USER root", "USER appuser"))
#                 notes.append("[deterministic] Dockerfile hardened")
#                 changed.append("Dockerfile")

#         # (Your Terraform S3 fixes method goes here if you’ve added it)
#         # Example:
#         tf_root = (self.repo / "hackathon-vuln-app" / "terraform")
#         if tf_root.exists():
#             n_iac, c_iac = self._apply_iac_s3_fixes(tf_root)  # <- your previously added method
#             notes += n_iac
#             changed += c_iac

#         return notes, changed

#     # -------------------------------------------------
#     def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
#         prompt = f"You MUST output ONLY unified git diff patch.\nFix vulnerability:\n{item}"

#         try:
#             from agents.llm_bridge import assistant_factory
#             diff = assistant_factory().generate_patch(prompt)
#             diff = _sanitize_diff(diff)
#             return diff, False

#         except Exception as e:
#             print("[fixer] LLM error:", e)
#             return "", True

#     # -------------------------------------------------
#     def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
#         notes, changed_files = [], []

#         for tool, items in grouped.items():
#             for item in items:

#                 if not _is_autofix_severity(item.get("severity")):
#                     continue

#                 file_path = item.get("file") or item.get("path") or ""
#                 title = str(item.get("title", "")).lower()

#                 print(f"[fixer] vulnerability in: {file_path} -> {item.get('title')}")

#                 # Only Java handled by AST (optional); non-Java is handled elsewhere
#                 if not file_path.endswith(".java"):
#                     notes.append(f"[fixer] AST skipped (non-java finding): {item.get('title')}")
#                     continue

#                 diff, fallback = self._llm_propose_patch_for_item(item)

#                 # ======================================================
#                 # LLM invalid → AST structural fallback (now optional)
#                 # ======================================================
#                 if fallback or not diff or "--- a/" not in diff:

#                     if not self.ast_enabled:
#                         notes.append(f"[fixer] AST disabled; skipping fallback for: {item.get('title')}")
#                         continue

#                     notes.append(f"[fixer] LLM patch invalid → AST fallback: {item.get('title')}")

#                     # Normalize title for classifier
#                     if "sql" in title:
#                         item["title"] = "SQL injection"
#                     elif "command" in title or "exec" in title:
#                         item["title"] = "command injection"

#                     ast_result = self.ast_engine.apply_for_finding(item)
#                     notes.extend(ast_result.notes)
#                     changed_files.extend(ast_result.changed_files)

#                     # Compile validation after AST change
#                     if ast_result.ok and ast_result.changed_files:
#                         ok, msg = self.ast_engine.compile_validate()
#                         notes.append(msg)
#                         if not ok:
#                             notes.append("[fixer] compile failed after AST fix")

#                     continue

#                 # ======================================================
#                 # LLM patch apply path
#                 # ======================================================
#                 targets = _parse_diff_changed_files(diff)
#                 targets = [t.replace("a/", "").replace("b/", "") for t in targets]

#                 if not _patch_targets_repo(self.repo, targets):
#                     notes.append("[fixer] patch rejected outside repo")
#                     continue

#                 if _git_apply_patch(self.repo, diff):
#                     notes.append("[fixer] LLM patch applied")
#                     changed_files.extend(targets)
#                 else:
#                     # If LLM patch can't be applied
#                     if not self.ast_enabled:
#                         notes.append("[fixer] LLM patch failed and AST disabled; skipping fallback")
#                         continue

#                     notes.append("[fixer] LLM patch failed → AST fallback")

#                     ast_result = self.ast_engine.apply_for_finding(item)
#                     notes.extend(ast_result.notes)
#                     changed_files.extend(ast_result.changed_files)

#                     if ast_result.ok and ast_result.changed_files:
#                         ok, msg = self.ast_engine.compile_validate()
#                         notes.append(msg)
#                         if not ok:
#                             notes.append("[fixer] compile failed after AST fix")

#         return notes, list(set(changed_files))

#     # -------------------------------------------------
#     def apply(self, grouped):
#         notes, changed = [], []

#         n1, c1 = self._apply_deterministic_fixes()
#         notes += n1; changed += c1

#         n2, c2 = self._apply_llm_autofixes(grouped)
#         notes += n2; changed += c2

#         changed = list(set(changed))
#         self.out.mkdir(parents=True, exist_ok=True)
#         (self.out / "patch_manifest.json").write_text(
#             json.dumps({"files": changed, "notes": notes}, indent=2), encoding="utf-8"
#         )

#         print("[fixer] changed files:", changed)
#         return notes, changed


#     # # -------------------------------------------------
#     # def apply(self, grouped):
#     #     notes, changed = [], []

#     #     n1, c1 = self._apply_deterministic_fixes()
#     #     notes += n1
#     #     changed += c1

#     #     n2, c2 = self._apply_llm_autofixes(grouped)
#     #     notes += n2
#     #     changed += c2

#     #     changed = list(set(changed))

#     #     self.out.mkdir(parents=True, exist_ok=True)

#     #     (self.out / "patch_manifest.json").write_text(
#     #         json.dumps({"files": changed, "notes": notes}, indent=2)
#     #     )

#     #     print("[fixer] changed files:", changed)
#     #     return notes, changed


#     # --- inside class Fixer, add this method ---
#     def _apply_iac_s3_fixes(self, tf_root: Path):
#         """
#         Deterministic Terraform fixes for S3 buckets flagged by tfsec:
#           - AVD-AWS-0092: public ACL -> private
#           - AVD-AWS-0088/0132: add SSE (uses KMS if S3_KMS_KEY_ARN env provided; else SSE-S3)
#           - AVD-AWS-0086/87/91/93/0094: add aws_s3_bucket_public_access_block with all four booleans true
#         """
#         notes, changed = [], []
#         if not tf_root.exists():
#             return notes, changed
    
#         kms_arn = os.getenv("S3_KMS_KEY_ARN", "").strip()
    
#         # 1) In-place update for bucket resources across *.tf
#         for tf in tf_root.rglob("*.tf"):
#             text = tf.read_text(encoding="utf-8")
#             original = text
    
#             # (a) Prevent public ACLs
#             text = re.sub(r'acl\s*=\s*"public-read(-write)?"', 'acl = "private"', text)
    
#             # (b) Ensure SSE block (prefer KMS if provided; else SSE-S3)
#             def add_sse_block(match):
#                 block = match.group(0)
#                 if "server_side_encryption_configuration" in block:
#                     return block  # already present
#                 if kms_arn:
#                     sse = f'''
#       server_side_encryption_configuration {{
#         rule {{
#           apply_server_side_encryption_by_default {{
#             sse_algorithm     = "aws:kms"
#             kms_master_key_id = "{kms_arn}"
#           }}
#         }}
#       }}'''
#                 else:
#                     sse = '''
#       server_side_encryption_configuration {
#         rule {
#           apply_server_side_encryption_by_default {
#             sse_algorithm = "AES256"
#           }
#         }
#       }'''
#                 return re.sub(r'\}\s*$', f'{sse}\n}}', block, flags=re.S)
    
#             # inject SSE into each aws_s3_bucket resource
#             text = re.sub(
#                 r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[\s\S]*?\}',
#                 add_sse_block,
#                 text,
#                 flags=re.S
#             )
    
#             if text != original:
#                 tf.write_text(text, encoding="utf-8")
#                 notes.append(f"[iac] updated {tf}")
#                 changed.append(str(tf.relative_to(self.repo)))
    
#         # 2) Ensure Public Access Block is present (one per bucket)
#         pab_tf = tf_root / "s3_public_access_block.tf"
#         required = []
#         for tf in tf_root.rglob("*.tf"):
#             if tf == pab_tf:
#                 continue
#             src = tf.read_text(encoding="utf-8")
#             required += re.findall(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', src)
#         required = sorted(set(required))
    
#         want_body = ""
#         for name in required:
#             want_body += f'''
#     resource "aws_s3_bucket_public_access_block" "{name}_pab" {{
#       bucket = aws_s3_bucket.{name}.id
    
#       block_public_acls       = true
#       block_public_policy     = true
#       ignore_public_acls      = true
#       restrict_public_buckets = true
#     }}
#     '''.strip() + "\n\n"
    
#         if required:
#             current = pab_tf.read_text(encoding="utf-8") if pab_tf.exists() else ""
#             if current.strip() != want_body.strip():
#                 pab_tf.write_text(want_body.strip() + "\n", encoding="utf-8")
#                 notes.append(f"[iac] wrote {pab_tf.relative_to(self.repo)} for: {', '.join(required)}")
#                 changed.append(str(pab_tf.relative_to(self.repo)))
    
#         return notes, list(set(changed))

#     # --- in apply(self, grouped) insert this call (keep your existing order) ---
#     def apply(self, grouped):
#         notes, changed = [], []
    
#         n1, c1 = self._apply_deterministic_fixes()
#         notes += n1; changed += c1
    
#         # IaC S3 fixes
#         tf_root = (self.repo / "hackathon-vuln-app" / "terraform")
#         n_iac, c_iac = self._apply_iac_s3_fixes(tf_root)
#         notes += n_iac; changed += c_iac
    
#         n2, c2 = self._apply_llm_autofixes(grouped)
#         notes += n2; changed += c2
    
#         changed = list(set(changed))
#         self.out.mkdir(parents=True, exist_ok=True)
#         (self.out / "patch_manifest.json").write_text(
#             json.dumps({"files": changed, "notes": notes}, indent=2), encoding="utf-8"
#         )
#         print("[fixer] changed files:", changed)
#         return notes, changed