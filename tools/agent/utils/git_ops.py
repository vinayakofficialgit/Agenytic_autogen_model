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


# ---------- Text transforms (order matters) ----------

def _sanitize_patch(patch_text: str) -> str:
    """
    Minimal sanitization: normalize EOLs and remove Markdown code fences.
    Do NOT touch paths here.
    """
    t = patch_text.replace("\r\n", "\n").replace("\r", "\n")
    # Drop lines that are just code fences like ``` or ```lang
    t = re.sub(r"^\s*`{3,}.*\n?", "", t, flags=re.M)
    return t


def _html_unescape_all(text: str) -> str:
    """
    Unescape HTML entities in the entire patch AFTER headers have been normalized.
    Repeat a few times in case of double encoding.
    """
    prev = None
    cur = text
    for _ in range(3):
        prev = cur
        cur = (cur
               .replace("&lt;", "<").replace("&gt;", ">")
               .replace("&quot;", '"').replace("&#39;", "'")
               .replace("&amp;", "&"))
        if cur == prev:
            break
    return cur


# ---------- Path rewriting (bulletproof) ----------

def _rewrite_diff_git_line(line: str, prefix: str) -> str:
    """
    Normalize: diff --git a/<path> b/<path>
    """
    if not line.startswith("diff --git "):
        return line
    parts = line.strip().split()
    # Expected: ["diff", "--git", "a/...", "b/..."]
    if len(parts) >= 4 and parts[2].startswith("a/") and parts[3].startswith("b/"):
        a_path = parts[2][2:]
        b_path = parts[3][2:]
        if not (a_path.startswith(prefix) or a_path.startswith("/") or a_path.startswith("./")):
            a_path = prefix + a_path
        if not (b_path.startswith(prefix) or b_path.startswith("/") or b_path.startswith("./")):
            b_path = prefix + b_path
        return f"diff --git a/{a_path} b/{b_path}"
    return line


_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+(\S+)(.*)$")

def _rewrite_header_line(line: str, prefix: str) -> str:
    """
    Normalize any '--- <path>[<meta>]' or '+++ <path>[<meta>]' header.
    Preserve trailing metadata (tabs/timestamps).
    If header uses git-style 'a/' or 'b/', rewrite the core path too.
    """
    m = _HEADER_RE.match(line)
    if not m:
        return line

    mark, path, meta = m.groups()

    if path.startswith("a/"):
        core = path[2:]
        if not (core.startswith(prefix) or core.startswith("/") or core.startswith("./")):
            core = prefix + core
        return f"{mark} a/{core}{meta}"

    if path.startswith("b/"):
        core = path[2:]
        if not (core.startswith(prefix) or core.startswith("/") or core.startswith("./")):
            core = prefix + core
        return f"{mark} b/{core}{meta}"

    # Plain unified header: enforce prefix unless absolute/relative already
    if not (path.startswith(prefix) or path.startswith("/") or path.startswith("./")):
        path = prefix + path
    return f"{mark} {path}{meta}"


def _rewrite_patch_paths(patch_text: str, prefix: str) -> str:
    """
    PUBLIC helper (backward compatible):
    Rewrite ALL diff headers in the given patch text:
      - 'diff --git a/... b/...'
      - '--- a/<path>[meta]' / '+++ b/<path>[meta]'
      - '--- <path>[meta]'  / '+++ <path>[meta]'
    """
    out_lines = []
    for line in patch_text.split("\n"):
        if line.startswith("diff --git "):
            line = _rewrite_diff_git_line(line, prefix)
        elif line.startswith("--- ") or line.startswith("+++ "):
            line = _rewrite_header_line(line, prefix)
        out_lines.append(line)
    return "\n".join(out_lines)


# ---------- Main apply flow ----------

def ensure_branch_and_apply_diff(
    patch_path: pathlib.Path, module_prefix: Optional[str] = None
) -> str:
    """
    Create a new branch and apply a fully-rewritten patch (prefix enforced + HTML unescaped) once.
    """
    ensure_git_identity()
    br = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {br}")

    patch_path = pathlib.Path(patch_path).resolve()
    prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"

    # 1) Read & sanitize (normalize EOLs, drop code fences)
    txt = patch_path.read_text(encoding="utf-8", errors="ignore")
    txt = _sanitize_patch(txt)

    # 2) Rebuild ALL path headers across entire file
    txt = _rewrite_patch_paths(txt, prefix)

    # 3) Unescape HTML entities so body hunks match repo files
    txt = _html_unescape_all(txt)

    # Save final patch we will apply
    prefixed = patch_path.with_suffix(".prefixed.diff")
    prefixed.write_text(txt, encoding="utf-8")

    # Preview ENTIRE patch for full visibility
    run(f"wc -l {prefixed}")
    run(f"cat {prefixed}")

    # Dry-run check (non-fatal) then apply once
    run(f"git apply --check {prefixed} || true")
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