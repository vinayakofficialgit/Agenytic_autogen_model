from __future__ import annotations

import os
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

    # -------------------------------------------------
    def apply(self, grouped):
        notes, changed = [], []

        n1, c1 = self._apply_deterministic_fixes()
        notes += n1
        changed += c1

        n2, c2 = self._apply_llm_autofixes(grouped)
        notes += n2
        changed += c2

        changed = list(set(changed))

        self.out.mkdir(parents=True, exist_ok=True)

        (self.out / "patch_manifest.json").write_text(
            json.dumps({"files": changed, "notes": notes}, indent=2)
        )

        print("[fixer] changed files:", changed)
        return notes, changed