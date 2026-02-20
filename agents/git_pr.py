import subprocess

class GitPRAgent:
    def create_pr(self, files):
        if not files:
            return

        branch = "ai-security-fixes"

        subprocess.run(["git", "checkout", "-b", branch], check=False)

        for f in files:
            subprocess.run(["git", "add", f], check=False)

        subprocess.run(["git", "commit", "-m", "AI security auto fixes"], check=False)
        subprocess.run(["git", "push", "origin", branch], check=False)

        subprocess.run([
            "gh", "pr", "create",
            "--title", "AI Security Fixes",
            "--body", "Automated remediation by AI"
        ], check=False)