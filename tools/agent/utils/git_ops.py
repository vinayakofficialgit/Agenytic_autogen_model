import subprocess, time, os

def run(cmd):
    print(f"+ {cmd}")
    subprocess.check_call(cmd, shell=True)

def ensure_git_identity():
    try:
        subprocess.check_call('git config user.email', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        run('git config user.email "ci-bot@example.com"')
        run('git config user.name "CI Bot"')

def ensure_branch_and_apply_diff(patch_path):
    ensure_git_identity()
    br = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {br}")
    run(f"git apply --whitespace=fix {patch_path}")
    run(f"git add -A")
    run(f'git commit -m "Agentic AI autofix"')
    run(f"git push --set-upstream origin {br}")
    return br

def open_pr(branch, title, body):
    # Try gh CLI first
    try:
        out = subprocess.check_output(
            f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
            shell=True, stderr=subprocess.STDOUT
        ).decode()
        return out.strip()
    except Exception as e:
        print(f"gh not available or failed: {e}. PR not opened automatically.")
        return "(install gh to auto-open PR)"