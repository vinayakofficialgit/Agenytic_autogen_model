#!/usr/bin/env python3
import subprocess
import time
import os
import pathlib
import re


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
    """Repeated HTML unescaping until stable."""
    prev = None
    cur = text
    for _ in range(10):  # enough to unwrap nested escapes
        prev = cur
        cur = (cur
               .replace("&lt;", "<")
               .replace("&gt;", ">")
               .replace("&quot;", '"')
               .replace("&#39;", "'")
               .replace("&amp;", "&"))
        if cur == prev:
            break
    return cur


# ---------------------------------------------------------
#           PATH REWRITING (BULLETPROOF)
# ---------------------------------------------------------

HEADER = re.compile(r"^(---|\+\+\+)\s+(\S+)(.*)$")

def _normalize_header(line: str, prefix: str) -> str:
    m = HEADER.match(line)
    if not m:
        return line
    mark, path, meta = m.groups()

    # handle git-style a/ and b/
    if path.startswith("a/") or path.startswith("b/"):
        lead = path[:2]   # 'a/' or 'b/'
        core = path[2:]
        if not (core.startswith(prefix) or core.startswith("/") or core.startswith("./")):
            core = prefix + core
        return f"{mark} {lead}{core}{meta}"

    # plain unified header
    if not (
        path.startswith(prefix)
        or path.startswith("/")
        or path.startswith("./")
    ):
        path = prefix + path

    return f"{mark} {path}{meta}"


def _normalize_diff_git(line: str, prefix: str) -> str:
    if not line.startswith("diff --git "):
        return line

    parts = line.strip().split()
    # expect: diff --git a/foo b/bar
    if len(parts) >= 4 and parts[2].startswith("a/") and parts[3].startswith("b/"):
        a_path = parts[2][2:]
        b_path = parts[3][2:]
        if not a_path.startswith(prefix):
            a_path = prefix + a_path
        if not b_path.startswith(prefix):
            b_path = prefix + b_path
        return f"diff --git a/{a_path} b/{b_path}"

    return line


def _rewrite_patch_paths(text: str, prefix: str) -> str:
    """Normalize ALL headers across the file."""
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

def ensure_branch_and_apply_diff(patch_path: pathlib.Path, module_prefix=None) -> str:
    ensure_git_identity()

    branch = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {branch}")

    prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"

    # 1) load raw patch
    raw = pathlib.Path(patch_path).read_text(encoding="utf-8", errors="ignore")

    # 2) sanitize markdown & normalize EOL
    patched = _sanitize(raw)

    # 3) rewrite ALL headers (diff --git, ---/+++)
    patched = _rewrite_patch_paths(patched, prefix)

    # 4) NOW unescape HTML entities everywhere
    patched = _html_unescape_recursive(patched)

    # 5) write final patch
    out = patch_path.with_suffix(".prefixed.diff")
    out.write_text(patched, encoding="utf-8")

    # 6) Preview ENTIRE patch so CI logs show everything
    run(f"echo '--- FINAL PATCH START ---'")
    run(f"wc -l {out}")
    run(f"cat {out}")
    run(f"echo '--- FINAL PATCH END ---'")

    # 7) Dry run (non-fatal)
    run(f"git apply --check {out} || true")

    # 8) Apply for real
    run(f"git apply --whitespace=fix {out}")

    return branch