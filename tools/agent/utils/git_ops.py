#!/usr/bin/env python3
import subprocess
import time
import os
import pathlib
import re
import html
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
    # Drop any fence lines like ``` or ```lang entirely
    return re.sub(r"^\s*`{3,}.*$", "", text, flags=re.M)


def _html_unescape_recursive(text: str) -> str:
    """
    Fully unescape HTML entities so diff hunks match repo files.
    Use stdlib html.unescape repeatedly until no changes remain.
    """
    prev = None
    cur = text
    for _ in range(10):  # unwrap nested encodings (&amp;lt; -> &lt; -> <)
        prev = cur
        cur = html.unescape(cur)
        if cur == prev:
            break
    # Final defensive pass for common leftovers (rare but safe)
    cur = (cur
           .replace("&lt;", "<")
           .replace("&gt;", ">")
           .replace("&quot;", '"')
           .replace("&#39;", "'")
           .replace("&amp;", "&"))
    return cur


# ---------------------------------------------------------
#           PATH REWRITING (BULLETPROOF)
# ---------------------------------------------------------

_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+([^\t\r\n]+)(\t[^\r\n]+)?$")


def _strip_ab(path: str) -> str:
    """Strip leading a/ or b/ from a path."""
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _ensure_prefix(path: str, prefix: str) -> str:
    """Prepend module prefix if not already present."""
    if path.startswith(prefix) or path.startswith("/") or path.startswith("./"):
        return path
    return prefix + path


def _normalize_header(line: str, prefix: str) -> str:
    """
    Normalize ANY '--- path[<meta>]' or '+++ path[<meta>]' header.
    Always emits git-style a/ or b/ prefixed paths so that
    `git apply -p1` strips the a/b prefix and keeps the module prefix.
    """
    m = _HEADER_RE.match(line)
    if not m:
        return line

    mark, path, meta = m.groups()
    meta = meta or ""

    # Determine the correct git-style lead: --- → a/, +++ → b/
    lead = "a/" if mark == "---" else "b/"

    # Strip any existing a/ or b/ to get the core path
    core = _strip_ab(path)

    # Ensure module prefix is present
    core = _ensure_prefix(core, prefix)

    return f"{mark} {lead}{core}{meta}"


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$")


def _normalize_diff_git(line: str, prefix: str) -> str:
    """
    Normalize: diff --git a/<path> b/<path>
    """
    m = _DIFF_GIT_RE.match(line)
    if not m:
        return line

    a_path, b_path = m.groups()
    a_path = _ensure_prefix(a_path, prefix)
    b_path = _ensure_prefix(b_path, prefix)
    return f"diff --git a/{a_path} b/{b_path}"


def _extract_path_from_header(line: str) -> str:
    """Extract the file path from a --- or +++ header line."""
    path = line[4:].strip()
    if "\t" in path:
        path = path.split("\t", 1)[0]
    return _strip_ab(path)


def _rewrite_patch_paths(text: str, prefix: str) -> str:
    """
    PUBLIC helper:
    Normalize ALL headers across the patch and ensure every segment
    has a proper 'diff --git a/... b/...' header line.

    This guarantees `git apply -p1` will:
      1. Strip the a/b prefix
      2. Find the file at <prefix>/<relative-path> in the repo
    """
    out = []
    prev_was_diff_git = False

    for line in text.split("\n"):
        if line.startswith("diff --git "):
            line = _normalize_diff_git(line, prefix)
            prev_was_diff_git = True
        elif line.startswith("--- "):
            if not prev_was_diff_git:
                # Plain unified segment with no diff --git header.
                # Inject one so git treats it as a proper git diff.
                target = _extract_path_from_header(line)
                target = _ensure_prefix(target, prefix)
                out.append(f"diff --git a/{target} b/{target}")
            line = _normalize_header(line, prefix)
            prev_was_diff_git = False
        elif line.startswith("+++ "):
            line = _normalize_header(line, prefix)
        else:
            prev_was_diff_git = False
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

    # 3) Rewrite ALL headers (git-style and plain unified → proper git-style)
    patched = _rewrite_patch_paths(patched, prefix)

    # 4) Fully unescape HTML so hunks match actual files
    before_lt = patched.count("&lt;")
    before_gt = patched.count("&gt;")
    patched = _html_unescape_recursive(patched)
    after_lt = patched.count("&lt;")
    after_gt = patched.count("&gt;")

    # Diagnostics to prove we unescaped
    print(f"[patch-info] &lt; count: {before_lt} -> {after_lt} ; &gt; count: {before_gt} -> {after_gt}")

    # If anything still escaped, abort early with a clear message
    if after_lt or after_gt:
        final_preview = (patched[:4000] + "...\n") if len(patched) > 4000 else patched
        raise RuntimeError(
            "HTML entities remain in patch after unescape. "
            "Please check generators. Preview:\n" + final_preview
        )

    # 5) Write final patch
    out = patch_path.with_suffix(".prefixed.diff")
    out.write_text(patched, encoding="utf-8")

    # 6) Show full patch (so logs match exactly what git sees)
    run(f"echo '--- FINAL PATCH START ---'")
    run(f"wc -l {out}")
    run(f"cat {out}")
    run(f"echo '--- FINAL PATCH END ---'")

    # 7) Dry run (non-fatal)
    run(f"git apply --check {out} || true")

    # 8) Apply with -p1 (strips a/ and b/, preserves module prefix)
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
