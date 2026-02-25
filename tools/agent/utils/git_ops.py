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


def _sanitize_patch(patch_text: str) -> str:
    """
    Minimal sanitization: normalize EOLs and remove Markdown code fences.
    DO NOT unescape HTML here to avoid altering paths.
    """
    t = patch_text.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"^\s*`{3,}.*\n?", "", t, flags=re.M)
    return t


def _rewrite_patch_paths(patch_text: str, prefix: str) -> str:
    """
    Prefix repo paths with <prefix> (e.g., 'java-pilot-app/').
    Handles:
      - 'diff --git a/<path> b/<path>'
      - '--- a/<path>[<TAB>meta]' / '+++ b/<path>[<TAB>meta]'
      - '--- <path>[<TAB>meta]'  / '+++ <path>[<TAB>meta]'
    Preserves trailing metadata (like timestamps) after a tab.
    """
    text = patch_text

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

    # --- a/<path>[<TAB>meta]   and   +++ b/<path>[<TAB>meta]
    def repl_hdr_ab(mark: str):
        def _inner(m: re.Match) -> str:
            # m.group(1) is the path part, m.group(2) optional meta (tab + rest)
            head = add_prefix_if_needed(m.group(1))
            meta = m.group(2) or ""
            return f"{mark}{head}{meta}"
        return _inner

    text = re.sub(r"^--- a/([^\t\r\n]+)(\t[^\r\n]+)?$", repl_hdr_ab("--- a/"), text, flags=re.M)
    text = re.sub(r"^\+\+\+ b/([^\t\r\n]+)(\t[^\r\n]+)?$", repl_hdr_ab("+++ b/"), text, flags=re.M)

    # Plain headers: --- <path>[meta] and +++ <path>[meta]
    def repl_hdr_plain(mark: str):
        def _inner(m: re.Match) -> str:
            head = m.group(1)
            meta = m.group(2) or ""
            if not (head.startswith("a/") or head.startswith("b/")):
                head = add_prefix_if_needed(head)
            return f"{mark}{head}{meta}"
        return _inner

    text = re.sub(r"^--- ([^\t\r\n]+)(\t[^\r\n]+)?$", repl_hdr_plain("--- "), text, flags=re.M)
    text = re.sub(r"^\+\+\+ ([^\t\r\n]+)(\t[^\r\n]+)?$", repl_hdr_plain("+++ "), text, flags=re.M)

    return text


def ensure_branch_and_apply_diff(
    patch_path: pathlib.Path, module_prefix: Optional[str] = None
) -> str:
    """
    Create a new branch and apply a path-rewritten patch (prefix enforced) once.
    """
    ensure_git_identity()
    br = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {br}")

    patch_path = pathlib.Path(patch_path).resolve()
    prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"

    # Read, sanitize minimally, REWRITE paths BEFORE applying.
    txt = patch_path.read_text(encoding="utf-8", errors="ignore")
    txt = _sanitize_patch(txt)
    txt = _rewrite_patch_paths(txt, prefix)

    prefixed = patch_path.with_suffix(".prefixed.diff")
    prefixed.write_text(txt, encoding="utf-8")

    # Preview & dry-run check
    run(f"sed -n '1,150p' {prefixed}")
    run(f"git apply --check {prefixed} || true")

    # Apply once
    run(f"git apply --whitespace=fix {prefixed}")
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