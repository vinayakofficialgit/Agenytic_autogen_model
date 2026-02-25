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


# ---------------------------------------------------------
#               SAFE, GLOBAL TRANSFORMS
# ---------------------------------------------------------

def _sanitize(text: str) -> str:
    """Normalize EOLs and remove markdown ``` lines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"^\s*`{3,}.*$", "", text, flags=re.M)


def _html_unescape_recursive(text: str) -> str:
    """
    Fully unescape HTML entities (recursively) so diff hunks match repo files.
    Order matters: unescape & first, then the rest; repeat until stable.
    """
    prev = None
    cur = text
    for _ in range(10):  # handles nested/double encodings
        prev = cur
        cur = (cur
               .replace("&amp;", "&")
               .replace("&lt;", "<")
               .replace("&gt;", ">")
               .replace("&quot;", '"')
               .replace("&#39;", "'"))
        if cur == prev:
            break
    return cur


# ---------------------------------------------------------
#           PATH REWRITING (BULLETPROOF)
# ---------------------------------------------------------

_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+([^\t\r\n]+)(\t[^\r\n]+)?$")

def _normalize_header(line: str, prefix: str) -> str:
    """
    Normalize ANY '--- path[<meta>]' or '+++ path[<meta>]' header.
    Preserves trailing metadata (tabs/timestamps).
    """
    m = _HEADER_RE.match(line)
    if not m:
        return line

    mark, path, meta = m.groups()
    meta = meta or ""

    # Git-style a/ and b/
    if path.startswith("a/") or path.startswith("b/"):
        lead = path[:2]  # 'a/' or 'b/'
        core = path[2:]
        if not (core.startswith(prefix) or core.startswith("/") or core.startswith("./")):
            core = prefix + core
        return f"{mark} {lead}{core}{meta}"

    # Plain unified header
    if not (
        path.startswith(prefix) or path.startswith("/") or path.startswith("./")
    ):
        path = prefix + path

    return f"{mark} {path}{meta}"


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$")

def _normalize_diff_git(line: str, prefix: str) -> str:
    """
    Normalize: diff --git a/<path> b/<path>
    """
    m = _DIFF_GIT_RE.match(line)
    if not m:
        return line

    a_path, b_path = m.groups()
    if not (a_path.startswith(prefix) or a_path.startswith("/") or a_path.startswith("./")):
        a_path = prefix + a_path
    if not (b_path.startswith(prefix) or b_path.startswith("/") or b_path.startswith("./")):
        b_path = prefix + b_path
    return f"diff --git a/{a_path} b/{b_path}"


def _rewrite_patch_paths(text: str, prefix: str) -> str:
    """
    PUBLIC helper:
    Normalize ALL headers across the patch:
      - 'diff --git a/... b/...'
      - '--- a/<path>[meta]' / '+++ b/<path>[meta]'
      - '--- <path>[meta]'  / '+++ <path>[meta]'
    """
    out = []
    for line in text.split("\n"):
        if line.startswith("diff --git "):
            line = _normalize_diff_git(line, prefix)
        elif line.startswith("--- ") or line.startswith("+++ "):
            line = _normalize_header(line, prefix)
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------
#                    MAIN APPLY FLOW
# ---------------------------------------------------------

def ensure_branch_and_apply_diff(
    patch_path: pathlib.Path, module_prefix: Optional[str] = None
) -> str:
    """Create branch, rewrite patch, unescape HTML, apply once."""
    ensure_git_identity()

    branch = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {branch}")

    prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"

    # 1) Load raw patch
    raw = pathlib.Path(patch_path).read_text(encoding="utf-8", errors="ignore")

    # 2) Sanitize markdown + normalize EOLs
    patched = _sanitize(raw)

    # 3) Rewrite ALL headers
    patched = _rewrite_patch_paths(patched, prefix)

    # 4) Fully unescape HTML so hunks match actual files
    patched = _html_unescape_recursive(patched)

    # 5) Write final patch
    out = patch_path.with_suffix(".prefixed.diff")
    out.write_text(patched, encoding="utf-8")

    # 6) Show full patch
    run(f"echo '--- FINAL PATCH START ---'")
    run(f"wc -l {out}")
    run(f"cat {out}")
    run(f"echo '--- FINAL PATCH END ---'")

    # 7) Dry run (non-fatal)
    run(f"git apply --check {out} || true")

    # 8) Apply
    run(f"git apply --whitespace=fix {out}")

    return branch


def open_pr(branch: str, title: str, body: str) -> str:
    """Used by run_agent.py to open PR via gh."""
    try:
        out = subprocess.check_output(
            f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
            shell=True, stderr=subprocess.STDOUT
        ).decode()
        return out.strip()
    except Exception as e:
        print(f"gh failed: {e}")
        return "(install gh to auto-open PR)"