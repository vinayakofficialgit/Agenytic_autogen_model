# git_pr.py
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime


class GitPRAgent:
    """Creates branch, commits changes, pushes branch and opens PR."""

    def __init__(self, repo_root=Path(".")):
        self.repo = Path(repo_root)

    def _run(self, cmd):
        """Run command and print logs."""
        print("[git_pr] RUN:", " ".join(cmd))
        return subprocess.run(cmd, cwd=self.repo)

    def _load_manifest(self):
        manifest = self.repo / "agent_output" / "patch_manifest.json"
        if not manifest.exists():
            return {"files": []}
        try:
            return json.loads(manifest.read_text())
        except Exception:
            return {"files": []}

    def create_pr(self, files=None):
        run_id = os.getenv("GITHUB_RUN_ID", datetime.now().strftime("%Y%m%d%H%M"))
        branch = f"ai-autofix-{run_id}"
    
        self._run(["git", "checkout", "-B", branch])
    
        # add all
        self._run(["git", "add", "."])
    
        # allow empty commit
        self._run(["git", "commit", "--allow-empty", "-m", f"AI Security Autofix ({run_id})"])
    
        self._run(["git", "push", "origin", branch, "--set-upstream"])
    
        try:
            self._run(["gh", "pr", "create",
                       "--title", "AI Security Autofix",
                       "--body", "AI-generated remediation. Human review required."])
        except Exception:
            print("PR fallback: branch pushed only")

    # def create_pr(self, files=None):
    #         manifest = self._load_manifest()
    #         files = files or manifest.get("files", [])
    
    #         # fallback: add all changes if file list empty
    #         if not files:
    #             print("[git_pr] No explicit files → using git add .")
    #             self._run(["git", "add", "."])
    #         else:
    #             for f in files:
    #                 self._run(["git", "add", f])
    
    #         # detect changes
    #         status = subprocess.check_output(["git", "status", "--porcelain"]).decode()
    #         if not status.strip():
    #             print("[git_pr] No changes to commit")
    #             return
    
    #         run_id = os.getenv("GITHUB_RUN_ID", datetime.now().strftime("%Y%m%d%H%M"))
    #         branch = f"ai-autofix-{run_id}"
    
    #         # create branch
    #         self._run(["git", "checkout", "-B", branch])
    
    #         # commit
    #         self._run(["git", "commit", "-m", f"AI Security Autofix ({run_id})"])
    
    #         # push
    #         self._run(["git", "push", "origin", branch, "--set-upstream"])
    
    #         # try PR creation
    #         try:
    #             self._run([
    #                 "gh", "pr", "create",
    #                 "--title", "AI Security Autofix",
    #                 "--body", "AI-generated remediation. Human review required."
    #             ])
    #         except Exception:
    #             print("[git_pr] gh CLI missing → branch pushed only")
    
    #         print(f"[git_pr] Branch created: {branch}")

# # git_pr.py
# """
# Git PR Agent
# ------------
# Responsible for:
# ✔ Creating isolated autofix branch
# ✔ Committing changed files
# ✔ Opening PR with context
# ✔ Enforcing human-in-loop validation
# """

# import subprocess
# import json
# import os
# from pathlib import Path
# from datetime import datetime


# class GitPRAgent:

#     def __init__(self, repo_root=Path(".")):
#         """Initialize PR agent with repo root."""
#         self.repo = Path(repo_root)

#     # -------------------------------------------------
#     # Helper: run git command safely
#     # -------------------------------------------------
#     def _run(self, cmd):
#         """Run git command with safe logging."""
#         return subprocess.run(cmd, cwd=self.repo, check=False, capture_output=True)

#     # -------------------------------------------------
#     # Helper: branch exists
#     # -------------------------------------------------
#     def _branch_exists(self, branch):
#         """Check if git branch already exists."""
#         res = self._run(["git", "branch", "--list", branch])
#         return bool(res.stdout.strip())

#     # -------------------------------------------------
#     # Helper: load patch manifest
#     # -------------------------------------------------
#     def _load_manifest(self):
#         """Load patch_manifest.json produced by fixer."""
#         manifest = self.repo / "agent_output" / "patch_manifest.json"
#         if not manifest.exists():
#             return {"files": []}
#         try:
#             return json.loads(manifest.read_text())
#         except Exception:
#             return {"files": []}

#     # -------------------------------------------------
#     # Main PR creator
#     # -------------------------------------------------
#     def create_pr(self, files=None):
#         """Create branch, commit fixes, and open PR."""
#         manifest = self._load_manifest()
#         files = files or manifest.get("files", [])

#         if not files:
#             print("No files to commit → skipping PR")
#             return

#         # dynamic branch name
#         run_id = os.getenv("GITHUB_RUN_ID", datetime.now().strftime("%Y%m%d%H%M"))
#         branch = f"ai-autofix-{run_id}"

#         # create branch if not exists
#         if not self._branch_exists(branch):
#             self._run(["git", "checkout", "-b", branch])
#         else:
#             self._run(["git", "checkout", branch])

#         # add changed files
#         for f in files:
#             self._run(["git", "add", f])

#         # commit with traceability
#         self._run([
#             "git",
#             "commit",
#             "-m",
#             f"AI Security Autofix ({run_id})"
#         ])

#         # push branch
#         self._run(["git", "push", "origin", branch, "--set-upstream"])

#         # build PR body
#         body = """
# AI-generated security fixes.

# ⚠️ Human review required before merge.

# Includes:
# - Automated remediation patches
# - Security hardening updates
# - Severity-based fixes

# Review checklist:
# - Validate patch correctness
# - Confirm no functional regression
# - Approve or request changes
# """

#         # create PR
#         self._run([
#             "gh", "pr", "create",
#             "--title", "AI Security Autofix",
#             "--body", body,
#             "--label", "security",
#             "--label", "ai-generated",
#             "--label", "needs-review"
#         ])

#         print(f"PR created on branch {branch}")