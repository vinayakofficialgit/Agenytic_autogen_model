# agents/fixer.py
"""
Production-Grade Patch-First Fixer
Secure, targeted, validated, CI-safe.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set
import re
import os
import subprocess
import tempfile
import json
import yaml

# LLM bridge optional
try:
    from agents.llm_bridge import assistant_factory
except Exception:
    assistant_factory = None


# =========================================================
# SECURITY CONSTANTS
# =========================================================

MAX_PATCH_SIZE = 200_000  # 200 KB max per patch
FORBIDDEN_PATH_PREFIXES = [
    ".github/",
    ".git/",
    "agent_output/",
    "security-review/",
]
FORBIDDEN_FILES = {
    "decision.json",
}


# =========================================================
# HELPERS
# =========================================================

def _norm(p: str) -> str:
    if not p:
        return ""
    s = p.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _is_safe_path(repo_root: Path, path: str) -> bool:
    path = _norm(path)

    if path.startswith("/") or ".." in path:
        return False

    for prefix in FORBIDDEN_PATH_PREFIXES:
        if path.startswith(prefix):
            return False

    if Path(path).name in FORBIDDEN_FILES:
        return False

    return True


def _extract_unified_diff(text: str) -> str:
    if not text:
        return ""

    if len(text) > MAX_PATCH_SIZE:
        return ""

    if "--- " not in text or "+++ " not in text:
        return ""

    return text.strip() + "\n"


def _make_unified_diff_git(old_text: str, new_text: str, repo_rel: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "a.txt"
        b = Path(td) / "b.txt"
        a.write_text(old_text, encoding="utf-8")
        b.write_text(new_text, encoding="utf-8")

        cmd = [
            "git", "diff", "--no-index", "--unified=2", "--no-color",
            f"--label=a/{repo_rel}",
            f"--label=b/{repo_rel}",
            str(a), str(b)
        ]

        res = subprocess.run(cmd, capture_output=True, text=True)
        diff = res.stdout or ""
        return _extract_unified_diff(diff)


# =========================================================
# FIXER
# =========================================================

class Fixer:

    def __init__(
        self,
        config: Dict[str, Any],
        output_dir: Path,
        repo_root: Optional[Path] = None,
        targets: Optional[List[str]] = None,
    ):
        self.cfg = config or {}
        self.out = Path(output_dir)
        self.repo = repo_root or Path(".")
        self.patch_dir = self.out / "patches"
        self.patch_dir.mkdir(parents=True, exist_ok=True)

        self.targeted_only = bool(
            (self.cfg.get("remediation") or {}).get("targeted_only", True)
        )

        self.targets: Set[str] = set(_norm(t) for t in (targets or []) if t)

    # -----------------------------------------------------

    def _is_target(self, repo_rel: str) -> bool:
        if not self.targeted_only:
            return True
        if not self.targets:
            return True
        return _norm(repo_rel) in self.targets

    # -----------------------------------------------------

    def _write_patch(self, repo_rel: str, diff: str) -> Optional[str]:

        repo_rel = _norm(repo_rel)

        if not _is_safe_path(self.repo, repo_rel):
            print(f"[fixer] Blocked unsafe patch path: {repo_rel}")
            return None

        diff = _extract_unified_diff(diff)
        if not diff:
            print(f"[fixer] Invalid diff format for {repo_rel}")
            return None

        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", repo_rel)
        out_path = self.patch_dir / f"{safe_name}.patch"

        out_path.write_text(diff, encoding="utf-8")
        return str(out_path)

    # -----------------------------------------------------

    def apply(self, findings: Any) -> Dict[str, Any]:

        emitted: List[str] = []
        notes: List[str] = []

        print("[fixer] Starting remediation...")

        # Only deterministic infra patches in production version
        # LLM patches optional and must be enabled

        for path in self.targets:
            file_path = self.repo / path
            if not file_path.exists():
                continue

            if not self._is_target(path):
                continue

            try:
                original = file_path.read_text(encoding="utf-8")
            except Exception:
                continue

            # Example deterministic hardening:
            if path.endswith("Dockerfile"):
                new_text = self._fix_dockerfile(original)
            elif path.endswith(".tf"):
                new_text = self._fix_tf(original)
            elif path.endswith((".yaml", ".yml")):
                new_text = self._fix_k8s(original)
            else:
                continue

            if new_text != original:
                diff = _make_unified_diff_git(original, new_text, path)
                patch_path = self._write_patch(path, diff)
                if patch_path:
                    emitted.append(patch_path)

        (self.out / "remediation_changes.txt").write_text(
            "\n".join(emitted) if emitted else "(none)",
            encoding="utf-8"
        )

        print(f"[fixer] Completed. Patches: {len(emitted)}")

        return {"changed": bool(emitted), "files": emitted}

    # -----------------------------------------------------

    def _fix_dockerfile(self, text: str) -> str:
        if "USER" not in text:
            return text + "\nUSER appuser\n"
        return text

    def _fix_tf(self, text: str) -> str:
        return re.sub(
            r'0\.0\.0\.0/0',
            '10.0.0.0/24',
            text
        )

    def _fix_k8s(self, text: str) -> str:
        if "runAsNonRoot" not in text:
            return text + "\nsecurityContext:\n  runAsNonRoot: true\n"
        return text