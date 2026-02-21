# git_pr.py
"""
Git PR Agent
------------
Responsible for:
✔ Creating isolated autofix branch
✔ Committing changed files
✔ Opening PR with context
✔ Enforcing human-in-loop validation
"""

import subprocess
import json
import os
from pathlib import Path
from datetime import datetime


class GitPRAgent:

    def __init__(self, repo_root=Path(".")):
        """Initialize PR agent with repo root."""
        self.repo = Path(repo_root)

    # -------------------------------------------------
    # Helper: run git command safely
    # -------------------------------------------------
    def _run(self, cmd):
        """Run git command with safe logging."""
        return subprocess.run(cmd, cwd=self.repo, check=False, capture_output=True)

    # -------------------------------------------------
    # Helper: branch exists
    # -------------------------------------------------
    def _branch_exists(self, branch):
        """Check if git branch already exists."""
        res = self._run(["git", "branch", "--list", branch])
        return bool(res.stdout.strip())

    # -------------------------------------------------
    # Helper: load patch manifest
    # -------------------------------------------------
    def _load_manifest(self):
        """Load patch_manifest.json produced by fixer."""
        manifest = self.repo / "agent_output" / "patch_manifest.json"
        if not manifest.exists():
            return {"files": []}
        try:
            return json.loads(manifest.read_text())
        except Exception:
            return {"files": []}

    # -------------------------------------------------
    # Main PR creator
    # -------------------------------------------------
    def create_pr(self, files=None):
        """Create branch, commit fixes, and open PR."""
        manifest = self._load_manifest()
        files = files or manifest.get("files", [])

        if not files:
            print("No files to commit → skipping PR")
            return

        # dynamic branch name
        run_id = os.getenv("GITHUB_RUN_ID", datetime.now().strftime("%Y%m%d%H%M"))
        branch = f"ai-autofix-{run_id}"

        # create branch if not exists
        if not self._branch_exists(branch):
            self._run(["git", "checkout", "-b", branch])
        else:
            self._run(["git", "checkout", branch])

        # add changed files
        for f in files:
            self._run(["git", "add", f])

        # commit with traceability
        self._run([
            "git",
            "commit",
            "-m",
            f"AI Security Autofix ({run_id})"
        ])

        # push branch
        self._run(["git", "push", "origin", branch, "--set-upstream"])

        # build PR body
        body = """
AI-generated security fixes.

⚠️ Human review required before merge.

Includes:
- Automated remediation patches
- Security hardening updates
- Severity-based fixes

Review checklist:
- Validate patch correctness
- Confirm no functional regression
- Approve or request changes
"""

        # create PR
        self._run([
            "gh", "pr", "create",
            "--title", "AI Security Autofix",
            "--body", body,
            "--label", "security",
            "--label", "ai-generated",
            "--label", "needs-review"
        ])

        print(f"PR created on branch {branch}")