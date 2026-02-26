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
    for _ in range(10):
        prev = cur
        cur = html.unescape(cur)
        if cur == prev:
            break
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
    Normalize '--- path' or '+++ path' headers.
    Always emits git-style a/ or b/ so `git apply -p1` works:
      -p1 strips a/ or b/ → leaves <prefix>/<relative-path>
    """
    m = _HEADER_RE.match(line)
    if not m:
        return line

    mark, path, meta = m.groups()
    meta = meta or ""

    lead = "a/" if mark == "---" else "b/"
    core = _strip_ab(path)
    core = _ensure_prefix(core, prefix)

    return f"{mark} {lead}{core}{meta}"


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$")


def _normalize_diff_git(line: str, prefix: str) -> str:
    """Normalize: diff --git a/<path> b/<path>"""
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
    Normalize ALL headers across the patch and ensure every segment
    has a proper 'diff --git a/... b/...' header line.

    CRITICAL: The seen_diff_git flag is ONLY reset when we reach a
    '--- ' line. Intermediate lines like 'index ...', 'old mode ...',
    'new mode ...' appear between 'diff --git' and '---' and must
    NOT reset the flag — otherwise we inject duplicate headers which
    corrupts the patch.
    """
    out = []
    seen_diff_git = False

    for line in text.split("\n"):
        if line.startswith("diff --git "):
            line = _normalize_diff_git(line, prefix)
            seen_diff_git = True
        elif line.startswith("--- "):
            if not seen_diff_git:
                # Plain unified segment missing a diff --git header.
                # Inject one so git treats it as a proper git diff.
                target = _extract_path_from_header(line)
                target = _ensure_prefix(target, prefix)
                out.append(f"diff --git a/{target} b/{target}")
            line = _normalize_header(line, prefix)
            # Reset ONLY here — we've consumed the diff --git context
            seen_diff_git = False
        elif line.startswith("+++ "):
            line = _normalize_header(line, prefix)
        # NOTE: Do NOT reset seen_diff_git on other lines.
        # Lines like 'index abc..def', 'old mode', 'new mode', 'similarity'
        # appear between 'diff --git' and '---' and must not clear the flag.
        out.append(line)

    return "\n".join(out)


# ---------------------------------------------------------
#              PATCH VALIDATION
# ---------------------------------------------------------

def _validate_patch(text: str) -> list:
    """
    Light structural validation of a unified diff.
    Returns a list of warning strings (empty = looks OK).
    """
    warnings = []
    lines = text.split("\n")
    n = len(lines)

    # Check for duplicate consecutive diff --git headers
    prev_diff_git = False
    for i, line in enumerate(lines, 1):
        if line.startswith("diff --git "):
            if prev_diff_git:
                warnings.append(f"Line {i}: consecutive diff --git without --- header")
            prev_diff_git = True
        elif line.startswith("--- "):
            prev_diff_git = False
        elif line.strip() == "":
            pass  # blank lines between segments are OK
        else:
            # intermediate meta lines (index, mode, etc.) keep the flag
            if not (line.startswith("index ") or line.startswith("old mode") or
                    line.startswith("new mode") or line.startswith("similarity") or
                    line.startswith("rename") or line.startswith("copy")):
                prev_diff_git = False

    # Check hunk body lines
    in_hunk = False
    for i, line in enumerate(lines, 1):
        if line.startswith("@@ "):
            in_hunk = True
            continue
        if line.startswith("diff --git ") or line.startswith("--- ") or line.startswith("+++ "):
            in_hunk = False
            continue
        if in_hunk and line:
            if line[0] not in (' ', '+', '-', '\\'):
                warnings.append(f"Line {i}: unexpected char '{line[0]}' in hunk: {line[:80]}")

    return warnings


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

    # 3) Rewrite ALL headers (plain unified → proper git-style a/b)
    patched = _rewrite_patch_paths(patched, prefix)

    # 4) Fully unescape HTML so hunks match actual files
    before_lt = patched.count("&lt;")
    before_gt = patched.count("&gt;")
    patched = _html_unescape_recursive(patched)
    after_lt = patched.count("&lt;")
    after_gt = patched.count("&gt;")

    print(f"[patch-info] &lt; count: {before_lt} -> {after_lt} ; &gt; count: {before_gt} -> {after_gt}")

    if after_lt or after_gt:
        final_preview = (patched[:4000] + "...\n") if len(patched) > 4000 else patched
        raise RuntimeError(
            "HTML entities remain in patch after unescape. "
            "Please check generators. Preview:\n" + final_preview
        )

    # 5) Validate patch structure before writing
    warnings = _validate_patch(patched)
    if warnings:
        print("[patch-validation] Warnings found:")
        for w in warnings:
            print(f"  WARNING: {w}")
        # Dump numbered lines for debugging
        print("[patch-content-debug]")
        for idx, line in enumerate(patched.split("\n"), 1):
            print(f"  {idx:4d}: {line}")

    # 6) Write final patch
    out = patch_path.with_suffix(".prefixed.diff")
    out.write_text(patched, encoding="utf-8")

    # 7) Show full patch (so logs match exactly what git sees)
    run(f"echo '--- FINAL PATCH START ---'")
    run(f"wc -l {out}")
    run(f"cat {out}")
    run(f"echo '--- FINAL PATCH END ---'")

    # 8) Dry run (non-fatal, with verbose for diagnostics)
    run(f"git apply --check -v {out} || true")

    # 9) Apply (-p1 strips a/ b/, preserves module prefix)
    run(f"git apply --whitespace=fix -v {out}")

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
