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
        subprocess.check_call(
            "git config user.email",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        run('git config user.email "ci-bot@example.com"')
        run('git config user.name "CI Bot"')


def _rewrite_patch_paths(patch_text: str, prefix: str) -> str:
    """
    Prefix repo paths in unified diffs with <prefix> (e.g., 'java-pilot-app/').
    Handles:
      - 'diff --git a/<path> b/<path>'
      - '--- a/<path>' / '+++ b/<path>'
      - '--- <path>'  / '+++ <path>'
    Normalizes line endings to LF.
    """
    text = patch_text.replace("\r\n", "\n").replace("\r", "\n")

    def add_prefix_if_needed(p: str) -> str:
        if p.startswith(prefix) or p.startswith("/") or p.startswith("./"):
            return p
        return prefix + p

    # diff --git a/<path> b/<path>
    def repl_diff(m: re.Match) -> str:
        a_path = add_prefix_if_needed(m.group(1))
        b_path = add_prefix_if_needed(m.group(2))
        return f"diff --git a/{a_path} b/{b_path}"

    text = re.sub(r"^diff --git a/(\S+) b/(\S+)$", repl_diff, text, flags=re.M)

    # --- a/<path>  and  +++ b/<path>
    def repl_hdr_ab(m: re.Match) -> str:
        side = m.group(1)  # '--- a/' or '+++ b/'
        pth = add_prefix_if_needed(m.group(2))
        return f"{side}{pth}"

    text = re.sub(r"^(--- a/)(\S+)$", repl_hdr_ab, text, flags=re.M)
    text = re.sub(r"^(\+\+\+ b/)(\S+)$", repl_hdr_ab, text, flags=re.M)

    # Plain headers: --- <path>  and  +++ <path>
    def repl_hdr_plain(m: re.Match) -> str:
        mark = m.group(1)  # '--- ' or '+++ '
        pth = m.group(2)
        if pth.startswith("a/") or pth.startswith("b/"):
            return f"{mark}{pth}"
        pth = add_prefix_if_needed(pth)
        return f"{mark}{pth}"

    text = re.sub(r"^(--- )([^\t\n\r]+)$", repl_hdr_plain, text, flags=re.M)
    text = re.sub(r"^(\+\+\+ )([^\t\n\r]+)$", repl_hdr_plain, text, flags=re.M)

    return text


def ensure_branch_and_apply_diff(
    patch_path: pathlib.Path, module_prefix: Optional[str] = None
) -> str:
    """
    Create a new branch, try to apply the patch. If it fails,
    rewrite paths with the module prefix (env APP_DIR or 'java-pilot-app/') and retry once.
    """
    ensure_git_identity()
    br = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {br}")

    patch_path = pathlib.Path(patch_path).resolve()

    # Preview & validate BEFORE first apply
    run(f"sed -n '1,150p' {patch_path}")
    run(f"git apply --check {patch_path} || true")

    try:
        run(f"git apply --whitespace=fix {patch_path}")
        return br
    except subprocess.CalledProcessError:
        # Fallback: rewrite paths and retry
        prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"
        print(f"Patch apply failed once. Retrying with module prefix '{prefix}' ...")
        txt = patch_path.read_text(encoding="utf-8", errors="ignore")
        txt = txt.replace("\r\n", "\n").replace("\r", "\n")
        txt2 = _rewrite_patch_paths(txt, prefix)
        patched = patch_path.with_suffix(".prefixed.diff")
        patched.write_text(txt2, encoding="utf-8")

        # Preview & validate the prefixed patch BEFORE second apply
        run(f"sed -n '1,150p' {patched}")
        run(f"git apply --check {patched} || true")

        run(f"git apply --whitespace=fix {patched}")
        return br


def open_pr(branch: str, title: str, body: str) -> str:
    try:
        out = subprocess.check_output(
            f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
            shell=True,
            stderr=subprocess.STDOUT,
        ).decode()
        return out.strip()
    except Exception as e:
        print(f"gh not available or failed: {e}. PR not opened automatically.")
        return "(install gh to auto-open PR)"