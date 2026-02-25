#!/usr/bin/env python3
import subprocess
import time
import os
import pathlib
import re
from typing import Optional

def run(cmd: str):
    print(f"+ {cmd}")
    subprocess.check_call(cmd, shell=True)

def ensure_git_identity():
    try:
        subprocess.check_call('git config user.email', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        run('git config user.email "ci-bot@example.com"')
        run('git config user.name "CI Bot"')

def _rewrite_patch_paths(patch_text: str, prefix: str) -> str:
    """
    Prefix repo paths in unified diffs with `<prefix>` (e.g., 'java-pilot-app/').
    Handles:
      - 'diff --git a/<path> b/<path>'
      - '--- <path>' / '+++ <path>'
    Leaves already-prefixed, absolute, or a/ b/ paths intact.
    """
    def needs_prefix(p: str) -> bool:
        return not (
            p.startswith(prefix) or
            p.startswith("a/") or
            p.startswith("b/") or
            p.startswith("/") or
            p.startswith("./")
        )

    # diff --git a/... b/...
    def repl_diff(m):
        a_path = m.group(2)
        b_path = m.group(4)
        if needs_prefix(a_path):
            a_path = prefix + a_path
        if needs_prefix(b_path):
            b_path = prefix + b_path
        return f"{m.group(1)}{a_path} {m.group(3)}{b_path}"

    text = re.sub(r'^(diff --git a/)(\S+)( b/)(\S+)$', repl_diff, patch_text, flags=re.M)

    # --- path / +++ path
    def repl_hdr(m):
        mark = m.group(1)  # '--- ' or '+++ '
        pth  = m.group(2)
        if needs_prefix(pth):
            pth = prefix + pth
        return f"{mark}{pth}"

    text = re.sub(r'^(--- )([^\t\n\r]+)$', repl_hdr, text, flags=re.M)
    text = re.sub(r'^(\+\+\+ )([^\t\n\r]+)$', repl_hdr, text, flags=re.M)
    return text

def ensure_branch_and_apply_diff(patch_path: pathlib.Path, module_prefix: Optional[str] = None) -> str:
    """
    Create a new branch, try to apply the patch. If it fails,
    rewrite paths with the module prefix (default from env APP_DIR or 'java-pilot-app/') and retry once.
    """
    ensure_git_identity()
    br = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {br}")

    patch_path = pathlib.Path(patch_path).resolve()
    try:
        run(f"git apply --whitespace=fix {patch_path}")
        return br
    except subprocess.CalledProcessError:
        # Fallback: rewrite paths and retry
        prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"
        print(f"Patch apply failed once. Retrying with module prefix '{prefix}' ...")
        txt = patch_path.read_text(encoding="utf-8", errors="ignore")
        txt2 = _rewrite_patch_paths(txt, prefix)
        patched = patch_path.with_suffix(".prefixed.diff")
        patched.write_text(txt2, encoding="utf-8")
        run(f"git apply --whitespace=fix {patched}")
        return br

def open_pr(branch: str, title: str, body: str) -> str:
    # Try gh CLI
    try:
        out = subprocess.check_output(
            f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
            shell=True, stderr=subprocess.STDOUT
        ).decode()
        return out.strip()
    except Exception as e:
        print(f"gh not available or failed: {e}. PR not opened automatically.")
        return "(install gh to auto-open PR)"

# import subprocess, time, os

# def run(cmd):
#     print(f"+ {cmd}")
#     subprocess.check_call(cmd, shell=True)

# def ensure_git_identity():
#     try:
#         subprocess.check_call('git config user.email', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     except subprocess.CalledProcessError:
#         run('git config user.email "ci-bot@example.com"')
#         run('git config user.name "CI Bot"')

# def ensure_branch_and_apply_diff(patch_path):
#     ensure_git_identity()
#     br = f"ai-autofix-{int(time.time())}"
#     run(f"git checkout -b {br}")
#     run(f"git apply --whitespace=fix {patch_path}")
#     run(f"git add -A")
#     run(f'git commit -m "Agentic AI autofix"')
#     run(f"git push --set-upstream origin {br}")
#     return br

# def open_pr(branch, title, body):
#     # Try gh CLI first
#     try:
#         out = subprocess.check_output(
#             f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
#             shell=True, stderr=subprocess.STDOUT
#         ).decode()
#         return out.strip()
#     except Exception as e:
#         print(f"gh not available or failed: {e}. PR not opened automatically.")
#         return "(install gh to auto-open PR)"