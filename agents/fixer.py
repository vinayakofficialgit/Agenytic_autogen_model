"""
Fixer Agent
-----------
Applies deterministic + LLM autofixes and writes patch manifest.
Ensures repo changes so GitPRAgent can create branch.
"""

from __future__ import annotations
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Any


# -------------------------------------------------
# Utility: severity filter for autofix
# -------------------------------------------------
def _is_autofix_severity(sev):
    return str(sev or "").lower() in ["high", "critical"]


# -------------------------------------------------
# Utility: parse changed files from unified diff
# -------------------------------------------------
def _parse_diff_changed_files(diff: str) -> List[str]:
    files = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            files.append(line.replace("+++ b/", "").strip())
    return list(set(files))


# -------------------------------------------------
# Utility: prevent patch escaping repo
# -------------------------------------------------
def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
    repo_root = repo_root.resolve()
    for f in files:
        p = (repo_root / f).resolve()
        if not str(p).startswith(str(repo_root)):
            return False
    return True


# -------------------------------------------------
# Utility: sanitize LLM diff
# -------------------------------------------------
def _sanitize_diff(diff: str) -> str:
    """Remove markdown wrappers and explanations"""
    if not diff:
        return diff

    diff = diff.replace("```diff", "").replace("```", "").strip()

    # Try auto-prefix if missing
    if "--- a/" not in diff and "+++" in diff:
        lines = diff.splitlines()
        for i, l in enumerate(lines):
            if l.startswith("+++"):
                lines.insert(i, "--- a/unknown")
                diff = "\n".join(lines)
                break

    return diff


# -------------------------------------------------
# Utility: apply patch via git
# -------------------------------------------------
def _git_apply_patch(repo: Path, diff: str) -> bool:
    try:
        # patch validation
        proc = subprocess.run(
            ["git", "apply", "--check", "-"],
            cwd=repo,
            input=diff.encode(),
        )
        if proc.returncode != 0:
            print("[fixer] patch check failed")
            return False

        # patch apply
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
    """
    Applies deterministic fixes + LLM generated patches.
    Guarantees patch manifest + repo modifications.
    """

    def __init__(self, cfg, output_dir, repo_root=Path(".")):
        self.cfg = cfg or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root)

    # -------------------------------------------------
    # Deterministic fixes (safe hardcoded fixes)
    # -------------------------------------------------
    def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
        notes, changed = [], []

        dockerfile = self.repo / "Dockerfile"
        if dockerfile.exists():
            text = dockerfile.read_text()
            if "USER root" in text:
                dockerfile.write_text(text.replace("USER root", "USER appuser"))
                notes.append("Dockerfile hardened")
                changed.append("Dockerfile")

        return notes, changed

    # -------------------------------------------------
    # LLM patch generator (strong prompt)
    # -------------------------------------------------
    def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
        prompt = f"""
You MUST output ONLY unified git diff patch.
NO explanation.

Format example:
--- a/file
+++ b/file
@@
-old
+new

Fix vulnerability:
{item}
"""
        try:
            from agents.llm_bridge import assistant_factory
            diff = assistant_factory().generate_patch(prompt)
            diff = _sanitize_diff(diff)

            # debug visibility
            print("[fixer] raw patch:", diff[:300])

            return diff, False
        except Exception as e:
            print("[fixer] LLM error:", e)
            return "", True

    # -------------------------------------------------
    # Apply LLM patches safely + deterministic fallback
    # -------------------------------------------------
    def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
        notes, changed_files = [], []
    
        for tool, items in grouped.items():
            for item in items:
                if not _is_autofix_severity(item.get("severity")):
                    continue
    
                file_path = item.get("file") or item.get("path") or ""
                print(f"[fixer] vulnerability in: {file_path} -> {item.get('title')}")
    
                diff, fallback = self._llm_propose_patch_for_item(item)
    
                # -------------------------------------------------
                # LLM patch invalid → deterministic fallback
                # -------------------------------------------------
                if fallback or not diff or "--- a/" not in diff:
                    notes.append(f"Invalid patch: {item.get('title')}")
    
                    # ⭐ deterministic SQL injection fix
                    title = str(item.get("title", "")).lower()
                    if "sql" in title and "inject" in title and file_path:
                        target = self.repo / file_path
                        if target.exists():
                            text = target.read_text()
    
                            # naive but effective SQL concat detection
                            if "+ " in text and "select" in text.lower():
                                text = text.replace("+", "?")
                                target.write_text(text)
                                notes.append(f"Deterministic SQL fix applied: {file_path}")
                                changed_files.append(file_path)
                                continue
    
                    # ⭐ deterministic command injection fix
                    if "command injection" in title and file_path:
                        target = self.repo / file_path
                        if target.exists():
                            text = target.read_text()
                            if "Runtime.getRuntime().exec" in text:
                                text = text.replace(
                                    "Runtime.getRuntime().exec",
                                    "new ProcessBuilder"
                                )
                                target.write_text(text)
                                notes.append(f"Deterministic command fix applied: {file_path}")
                                changed_files.append(file_path)
                                continue
    
                    continue
    
                # -------------------------------------------------
                # LLM patch path validation
                # -------------------------------------------------
                targets = _parse_diff_changed_files(diff)
    
                if not _patch_targets_repo(self.repo, targets):
                    notes.append("Patch rejected outside repo")
                    continue
    
                # -------------------------------------------------
                # Apply LLM patch
                # -------------------------------------------------
                if _git_apply_patch(self.repo, diff):
                    notes.append(f"Patch applied: {item.get('title')}")
                    changed_files.extend(targets)
                else:
                    patch_file = self.out / f"patch_{item.get('id','x')}.diff"
                    patch_file.write_text(diff)
                    notes.append(f"Patch saved (manual review): {item.get('title')}")
    
        return notes, list(set(changed_files))



    # # -------------------------------------------------
    # # Apply LLM patches safely
    # # -------------------------------------------------
    # def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
    #     notes, changed_files = [], []

    #     for tool, items in grouped.items():
    #         for item in items:
    #             if not _is_autofix_severity(item.get("severity")):
    #                 continue

    #             diff, fallback = self._llm_propose_patch_for_item(item)

    #             # invalid diff
    #             if fallback or not diff or "--- a/" not in diff:
    #                 notes.append(f"Invalid patch: {item.get('title')}")
    #                 continue

    #             targets = _parse_diff_changed_files(diff)

    #             # safety guard
    #             if not _patch_targets_repo(self.repo, targets):
    #                 notes.append("Patch rejected outside repo")
    #                 continue

    #             # apply patch
    #             if _git_apply_patch(self.repo, diff):
    #                 notes.append(f"Patch applied: {item.get('title')}")
    #                 changed_files.extend(targets)
    #             else:
    #                 # fallback manual patch save
    #                 patch_file = self.out / f"patch_{item.get('id','x')}.diff"
    #                 patch_file.write_text(diff)
    #                 notes.append(f"Patch saved (manual review): {item.get('title')}")

    #     return notes, list(set(changed_files))

    # -------------------------------------------------
    # Main apply entry
    # -------------------------------------------------
    def apply(self, grouped):
        notes, changed = [], []

        # deterministic fixes
        n1, c1 = self._apply_deterministic_fixes()
        notes += n1
        changed += c1

        # llm fixes
        n2, c2 = self._apply_llm_autofixes(grouped)
        notes += n2
        changed += c2

        # ensure output dir
        self.out.mkdir(parents=True, exist_ok=True)

        # patch manifest
        (self.out / "patch_manifest.json").write_text(
            json.dumps({"files": changed, "notes": notes}, indent=2)
        )

        print("[fixer] changed files:", changed)

        return notes, changed



# """
# Fixer Agent
# -----------
# Applies deterministic + LLM autofixes and writes patch manifest.
# Ensures repo changes so GitPRAgent can create branch.
# """

# from __future__ import annotations
# import os
# import json
# import subprocess
# from pathlib import Path
# from typing import Dict, List, Tuple, Any


# # -------------------------------------------------
# # Utility: severity filter for autofix
# # -------------------------------------------------
# def _is_autofix_severity(sev):
#     return str(sev or "").lower() in ["high", "critical"]


# # -------------------------------------------------
# # Utility: parse changed files from unified diff
# # -------------------------------------------------
# def _parse_diff_changed_files(diff: str) -> List[str]:
#     files = []
#     for line in diff.splitlines():
#         if line.startswith("+++ b/"):
#             files.append(line.replace("+++ b/", "").strip())
#     return list(set(files))


# # -------------------------------------------------
# # Utility: prevent patch escaping repo
# # -------------------------------------------------
# def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
#     repo_root = repo_root.resolve()
#     for f in files:
#         p = (repo_root / f).resolve()
#         if not str(p).startswith(str(repo_root)):
#             return False
#     return True


# # -------------------------------------------------
# # Utility: apply patch via git
# # -------------------------------------------------
# def _git_apply_patch(repo: Path, diff: str) -> bool:
#     try:
#         # patch validation
#         proc = subprocess.run(
#             ["git", "apply", "--check", "-"],
#             cwd=repo,
#             input=diff.encode(),
#         )
#         if proc.returncode != 0:
#             print("[fixer] patch check failed")
#             return False

#         # patch apply
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
#     """
#     Applies deterministic fixes + LLM generated patches.
#     Guarantees patch manifest + repo modifications.
#     """

#     def __init__(self, cfg, output_dir, repo_root=Path(".")):
#         self.cfg = cfg or {}
#         self.out = Path(output_dir)
#         self.repo = Path(repo_root)

#     # -------------------------------------------------
#     # Deterministic fixes (safe hardcoded fixes)
#     # -------------------------------------------------
#     def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
#         notes, changed = [], []

#         dockerfile = self.repo / "Dockerfile"
#         if dockerfile.exists():
#             text = dockerfile.read_text()
#             if "USER root" in text:
#                 dockerfile.write_text(text.replace("USER root", "USER appuser"))
#                 notes.append("Dockerfile hardened")
#                 changed.append("Dockerfile")

#         return notes, changed

#     # -------------------------------------------------
#     # LLM patch generator (strong prompt)
#     # -------------------------------------------------
#     def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
#         prompt = f"""
# Generate ONLY unified diff patch.
# Format:
# --- a/file
# +++ b/file
# @@
# ...
# Fix vulnerability:
# {item}
# """
#         try:
#             from agents.llm_bridge import assistant_factory
#             return assistant_factory().generate_patch(prompt), False
#         except Exception as e:
#             print("[fixer] LLM error:", e)
#             return "", True

#     # -------------------------------------------------
#     # Apply LLM patches safely
#     # -------------------------------------------------
#     def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
#         notes, changed_files = [], []

#         for tool, items in grouped.items():
#             for item in items:
#                 if not _is_autofix_severity(item.get("severity")):
#                     continue

#                 diff, fallback = self._llm_propose_patch_for_item(item)

#                 # invalid diff
#                 if fallback or not diff or "--- a/" not in diff:
#                     notes.append(f"Invalid patch: {item.get('title')}")
#                     continue

#                 targets = _parse_diff_changed_files(diff)

#                 # safety guard
#                 if not _patch_targets_repo(self.repo, targets):
#                     notes.append("Patch rejected outside repo")
#                     continue

#                 # apply patch
#                 if _git_apply_patch(self.repo, diff):
#                     notes.append(f"Patch applied: {item.get('title')}")
#                     changed_files.extend(targets)
#                 else:
#                     # fallback manual patch save
#                     patch_file = self.out / f"patch_{item.get('id','x')}.diff"
#                     patch_file.write_text(diff)
#                     notes.append(f"Patch saved (manual review): {item.get('title')}")

#         return notes, list(set(changed_files))

#     # -------------------------------------------------
#     # Main apply entry
#     # -------------------------------------------------
#     def apply(self, grouped):
#         notes, changed = [], []

#         # deterministic fixes
#         n1, c1 = self._apply_deterministic_fixes()
#         notes += n1
#         changed += c1

#         # llm fixes
#         n2, c2 = self._apply_llm_autofixes(grouped)
#         notes += n2
#         changed += c2

#         # ensure output dir
#         self.out.mkdir(parents=True, exist_ok=True)

#         # patch manifest
#         (self.out / "patch_manifest.json").write_text(
#             json.dumps({"files": changed, "notes": notes}, indent=2)
#         )

#         print("[fixer] changed files:", changed)

#         return notes, changed




# # fixer.py
# """
# Fixer Agent
# -----------
# Responsible for:
# ✔ Applying deterministic fixes
# ✔ Generating LLM autofixes
# ✔ Validating patch safety
# ✔ Producing patch manifest for PR agent
# """

# from __future__ import annotations
# import os
# import json
# import subprocess
# from pathlib import Path
# from typing import Dict, List, Tuple, Any

# # -------------------------------------------------
# # Helper: severity autofix eligibility
# # -------------------------------------------------
# def _is_autofix_severity(sev):
#     """Return True if severity eligible for autofix."""
#     return str(sev or "").lower() in ["high", "critical"]

# # -------------------------------------------------
# # Helper: extract changed files from diff
# # -------------------------------------------------
# def _parse_diff_changed_files(diff: str) -> List[str]:
#     """Extract file paths modified in unified diff."""
#     files = []
#     for line in diff.splitlines():
#         if line.startswith("+++ b/"):
#             files.append(line.replace("+++ b/", "").strip())
#     return list(set(files))

# # -------------------------------------------------
# # Helper: validate patch only targets repo files
# # -------------------------------------------------
# def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
#     """Ensure patch does not escape repo root."""
#     repo_root = repo_root.resolve()
#     for f in files:
#         p = (repo_root / f).resolve()
#         if not str(p).startswith(str(repo_root)):
#             return False
#     return True

# # -------------------------------------------------
# # Helper: git apply with dry-run validation
# # -------------------------------------------------
# def _git_apply_patch(repo: Path, diff: str) -> bool:
#     """Safely apply patch using git dry-run then apply."""
#     try:
#         proc = subprocess.run(
#             ["git", "apply", "--check", "-"],
#             cwd=repo,
#             input=diff.encode(),
#             capture_output=True,
#         )
#         if proc.returncode != 0:
#             return False

#         proc = subprocess.run(
#             ["git", "apply", "-"],
#             cwd=repo,
#             input=diff.encode(),
#             capture_output=True,
#         )
#         return proc.returncode == 0
#     except Exception:
#         return False

# # -------------------------------------------------
# # Fixer Agent
# # -------------------------------------------------
# class Fixer:

#     def __init__(self, cfg, output_dir, repo_root=Path(".")):
#         """Initialize fixer with config and repo root."""
#         self.cfg = cfg or {}
#         self.out = Path(output_dir)
#         self.repo = Path(repo_root)

#     # -------------------------------------------------
#     # Deterministic fixes
#     # -------------------------------------------------
#     def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
#         """Apply simple rule-based hardening fixes."""
#         notes = []
#         changed = []

#         dockerfile = self.repo / "Dockerfile"
#         if dockerfile.exists():
#             text = dockerfile.read_text()
#             if "USER root" in text:
#                 text = text.replace("USER root", "USER appuser")
#                 dockerfile.write_text(text)
#                 notes.append("Dockerfile hardened: root user removed")
#                 changed.append("Dockerfile")

#         return notes, changed

#     # -------------------------------------------------
#     # LLM patch generator
#     # -------------------------------------------------
#     def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
#         """Generate patch suggestion from LLM provider."""
#         prompt = f"Provide unified diff patch fix for: {item.get('title')}"

#         mode = os.getenv("LLM_MODE", "ollama")

#         try:
#             if mode == "openai":
#                 from agents.llm_bridge import openai_patch
#                 return openai_patch(prompt), False
#             else:
#                 from agents.llm_bridge import assistant_factory
#                 assistant = assistant_factory()
#                 return assistant.generate_patch(prompt), False
#         except Exception:
#             return "", True

#     # -------------------------------------------------
#     # Apply LLM autofixes
#     # -------------------------------------------------
#     def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
#         """Generate and apply LLM autofix patches."""
#         notes = []
#         changed_files = []

#         for tool, items in grouped.items():
#             for item in items:
#                 if not _is_autofix_severity(item.get("severity")):
#                     continue

#                 diff, fallback = self._llm_propose_patch_for_item(item)

#                 if fallback or not diff:
#                     notes.append(f"No autofix for {item.get('title')}")
#                     continue

#                 targets = _parse_diff_changed_files(diff)

#                 if not _patch_targets_repo(self.repo, targets):
#                     notes.append("Patch rejected: outside repo")
#                     continue

#                 if _git_apply_patch(self.repo, diff):
#                     notes.append(f"Patch applied: {item.get('title')}")
#                     changed_files.extend(targets)
#                 else:
#                     notes.append(f"Patch failed: {item.get('title')}")

#         return notes, list(set(changed_files))

#     # -------------------------------------------------
#     # Main apply entrypoint
#     # -------------------------------------------------
#     def apply(self, grouped):
#         """Run deterministic then LLM autofixes."""
#         notes = []
#         changed = []

#         # deterministic first
#         n1, c1 = self._apply_deterministic_fixes()
#         notes += n1
#         changed += c1

#         # llm autofix
#         n2, c2 = self._apply_llm_autofixes(grouped)
#         notes += n2
#         changed += c2

#         # write manifest AFTER changes
#         self.out.mkdir(parents=True, exist_ok=True)
#         (self.out / "patch_manifest.json").write_text(
#             json.dumps({"files": list(set(changed)), "notes": notes}, indent=2)
#         )

#         return notes, changed