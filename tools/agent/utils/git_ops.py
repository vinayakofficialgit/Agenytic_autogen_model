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
    Do NOT do any path changes here.
    """
    t = patch_text.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"^\s*`{3,}.*\n?", "", t, flags=re.M)  # drop lines like ``` or ```lang
    return t


def _html_unescape(text: str) -> str:
    """
    Unescape minimal HTML entities AFTER headers have been normalized.
    This ensures hunk bodies match repository files (e.g., pom.xml).
    """
    t = text
    # Unescape < and > first (common in XML/Java bodies)
    t = t.replace("&lt;", "<").replace("&gt;", ">")
    # Quotes
    t = t.replace("&quot;", '"').replace("&#39;", "'")
    # Ampersand last
    t = t.replace("&amp;", "&")
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


# Force ALL headers to have the prefix even if they escaped the regexes above (belt & suspenders)
_HEADER_LINE = re.compile(r"^(---|\+\+\+)\s+(\S+)(.*)$", re.M)

def _force_prefix_all_headers(text: str, prefix: str) -> str:
    def repl(m: re.Match) -> str:
        mark, path, meta = m.groups()
        if not (path.startswith(prefix) or path.startswith("a/") or path.startswith("b/") or path.startswith("/") or path.startswith("./")):
            path = prefix + path
        return f"{mark} {path}{meta}"
    return _HEADER_LINE.sub(repl, text)


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

    # 1) Read & sanitize
    txt = patch_path.read_text(encoding="utf-8", errors="ignore")
    txt = _sanitize_patch(txt)

    # 2) Rewrite paths (git-style + plain unified)
    txt = _rewrite_patch_paths(txt, prefix)

    # 3) Force prefix on ANY remaining ---/+++ headers (with or without metadata)
    txt = _force_prefix_all_headers(txt, prefix)

    # 4) Unescape HTML entities in BODY so hunks match real files
    txt = _html_unescape(txt)

    # Save final patch we will apply
    prefixed = patch_path.with_suffix(".prefixed.diff")
    prefixed.write_text(txt, encoding="utf-8")

    # Preview & dry-run check (show more for visibility)
    run(f"sed -n '1,300p' {prefixed}")
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