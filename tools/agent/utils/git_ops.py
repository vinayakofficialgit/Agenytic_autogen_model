#!/usr/bin/env python3
"""
git_ops.py — Branch creation, patch rewriting, self-healing apply.

Self-healing strategy when `git apply` fails:
  1. Fuzzy context repair: read the actual file, fix context lines
     in the patch that differ only by Unicode or whitespace.
  2. LLM regeneration: call OpenAI to produce a corrected diff
     using the real file content as ground truth.
  3. Partial apply (--reject): apply whatever hunks work.
"""
import subprocess
import time
import os
import pathlib
import re
import html
import json
import unicodedata
from typing import Optional, List, Tuple


# Optional: only needed for LLM self-healing fallback
try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


def run(cmd: str):
    print(f"+ {cmd}")
    subprocess.check_call(cmd, shell=True)


def run_capture(cmd: str) -> Tuple[int, str]:
    """Run a command, return (returncode, combined stdout+stderr).
    Does NOT raise on non-zero exit — caller decides what to do."""
    print(f"+ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode, output


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
    Fully unescape HTML entities so diff hunks match repo files.
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
                target = _extract_path_from_header(line)
                target = _ensure_prefix(target, prefix)
                out.append(f"diff --git a/{target} b/{target}")
            line = _normalize_header(line, prefix)
            seen_diff_git = False
        elif line.startswith("+++ "):
            line = _normalize_header(line, prefix)
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

    prev_diff_git = False
    for i, line in enumerate(lines, 1):
        if line.startswith("diff --git "):
            if prev_diff_git:
                warnings.append(f"Line {i}: consecutive diff --git without --- header")
            prev_diff_git = True
        elif line.startswith("--- "):
            prev_diff_git = False
        elif line.strip() == "":
            pass
        else:
            if not (line.startswith("index ") or line.startswith("old mode") or
                    line.startswith("new mode") or line.startswith("similarity") or
                    line.startswith("rename") or line.startswith("copy")):
                prev_diff_git = False

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
#     SELF-HEALING LAYER 1: FUZZY CONTEXT REPAIR
# ---------------------------------------------------------

# Unicode characters that LLMs commonly swap for ASCII equivalents
_UNICODE_TO_ASCII = {
    "\u2011": "-",   # non-breaking hyphen → ASCII hyphen
    "\u2010": "-",   # hyphen
    "\u2012": "-",   # figure dash
    "\u2013": "-",   # en dash
    "\u2014": "-",   # em dash
    "\u2015": "-",   # horizontal bar
    "\u2018": "'",   # left single quote
    "\u2019": "'",   # right single quote
    "\u201c": '"',   # left double quote
    "\u201d": '"',   # right double quote
    "\u00a0": " ",   # non-breaking space
    "\u2002": " ",   # en space
    "\u2003": " ",   # em space
    "\u2009": " ",   # thin space
    "\u200b": "",    # zero-width space
    "\ufeff": "",    # BOM
    "\u2026": "...", # ellipsis
}


def _normalize_unicode(text: str) -> str:
    """Normalize Unicode to ASCII-compatible form."""
    for uc, asc in _UNICODE_TO_ASCII.items():
        text = text.replace(uc, asc)
    return text


def _fuzzy_line_match(patch_line: str, file_line: str) -> bool:
    """Check if two lines match after normalizing Unicode and whitespace."""
    a = _normalize_unicode(patch_line).rstrip()
    b = _normalize_unicode(file_line).rstrip()
    if a == b:
        return True
    if a.strip() == b.strip():
        return True
    return False


def _extract_target_path(segment: str) -> Optional[str]:
    """Get the target file path from a +++ header (with a/b stripped)."""
    for line in segment.split("\n"):
        if line.startswith("+++ "):
            p = line[4:].strip()
            if "\t" in p:
                p = p.split("\t", 1)[0]
            return _strip_ab(p)
    return None


def _split_patch_segments(patch_text: str) -> List[str]:
    """Split a multi-file patch into per-file segments."""
    lines = patch_text.split("\n")
    segments = []
    current_start = None

    for i, line in enumerate(lines):
        if line.startswith("diff --git "):
            if current_start is not None:
                segments.append("\n".join(lines[current_start:i]))
            current_start = i

    if current_start is not None:
        segments.append("\n".join(lines[current_start:]))

    return [s for s in segments if s.strip()]


def _rejoin_segments(segments: List[str]) -> str:
    """Rejoin patch segments with proper spacing."""
    return "\n".join(s.rstrip("\n") for s in segments) + "\n"


def _repair_context_lines(segment: str, file_content: str) -> str:
    """
    For a single-file diff segment, replace context and removal lines
    with the actual content from the file if they fuzzy-match.
    This fixes Unicode mismatches (e.g., U+2011 vs ASCII hyphen).
    """
    file_lines = file_content.split("\n")
    patch_lines = segment.split("\n")
    result = []

    hunk_re = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")

    file_idx = 0
    in_hunk = False

    for pl in patch_lines:
        hm = hunk_re.match(pl)
        if hm:
            file_idx = int(hm.group(1)) - 1  # convert to 0-based
            in_hunk = True
            result.append(pl)
            continue

        if not in_hunk:
            result.append(pl)
            continue

        if pl.startswith(" "):
            # Context line — should match file content at file_idx
            if 0 <= file_idx < len(file_lines):
                actual = file_lines[file_idx]
                patch_content = pl[1:]  # strip leading space

                if patch_content.rstrip() != actual.rstrip():
                    if _fuzzy_line_match(patch_content, actual):
                        print(f"  [fuzzy-fix] line {file_idx+1}: replaced context "
                              f"'{patch_content.strip()[:50]}' → '{actual.strip()[:50]}'")
                        pl = " " + actual
            file_idx += 1

        elif pl.startswith("-"):
            # Removed line — must also match file content
            if 0 <= file_idx < len(file_lines):
                actual = file_lines[file_idx]
                patch_content = pl[1:]

                if patch_content.rstrip() != actual.rstrip():
                    if _fuzzy_line_match(patch_content, actual):
                        print(f"  [fuzzy-fix] line {file_idx+1}: replaced removal "
                              f"'{patch_content.strip()[:50]}' → '{actual.strip()[:50]}'")
                        pl = "-" + actual
            file_idx += 1

        elif pl.startswith("+"):
            # Added line — does NOT consume a file line
            pass

        result.append(pl)

    return "\n".join(result)


def _fuzzy_repair_patch(patch_text: str) -> str:
    """
    Read actual files from the repo and repair context/removal lines
    that differ only by Unicode or whitespace.
    """
    segments = _split_patch_segments(patch_text)
    repaired = []

    for seg in segments:
        target = _extract_target_path(seg)
        if target and os.path.isfile(target):
            try:
                content = pathlib.Path(target).read_text(encoding="utf-8", errors="ignore")
                print(f"[self-heal] Fuzzy-repairing context for: {target}")
                seg = _repair_context_lines(seg, content)
            except Exception as e:
                print(f"[self-heal] Could not read {target}: {e}")
        else:
            print(f"[self-heal] File not found for repair: {target}")
        repaired.append(seg)

    return _rejoin_segments(repaired)


# ---------------------------------------------------------
#     SELF-HEALING LAYER 2: LLM REGENERATION (OpenAI)
# ---------------------------------------------------------

_REGEN_SYSTEM = """You are a patch-repair assistant. You will be given:
1. The ACTUAL content of a file from the repository.
2. A diff segment that FAILED to apply to that file.
3. The INTENT of what the diff was trying to change.

Produce a corrected unified diff that:
- Has context lines that EXACTLY match the actual file content (byte-for-byte).
- Achieves the same fix intent as the original diff.
- Uses proper unified diff format with --- and +++ headers.
- Has correct @@ hunk headers with accurate line numbers.

Output ONLY the corrected diff, nothing else. No markdown fences."""


def _call_openai(prompt: str, system: str = _REGEN_SYSTEM) -> Optional[str]:
    """Call OpenAI API to regenerate a patch. Returns raw text or None."""
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key or not HAS_URLLIB:
        print("[self-heal] No OPENAI_API_KEY or urllib unavailable; skipping LLM regen.")
        return None

    model = os.getenv("OPENAI_MODEL", "gpt-4o")
    url = "https://api.openai.com/v1/chat/completions"
    payload = json.dumps({
        "model": model,
        "temperature": 0.0,
        "max_tokens": 4096,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"[self-heal] OpenAI call failed: {e}")
        return None


def _parse_failed_files(error_output: str) -> List[str]:
    """Extract file paths from 'error: patch failed: <path>:<line>' messages."""
    failed = []
    for m in re.finditer(r"error: patch failed: ([^:]+):", error_output):
        path = m.group(1).strip()
        if path not in failed:
            failed.append(path)
    return failed


def _describe_diff_intent(segment: str) -> str:
    """Summarize what a diff segment is trying to do."""
    added = []
    removed = []
    for line in segment.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return (
        f"REMOVED lines:\n" + "\n".join(removed[:20]) + "\n\n"
        f"ADDED lines:\n" + "\n".join(added[:20])
    )


def _llm_regenerate_failed_segments(
    patch_text: str, failed_files: List[str], prefix: str
) -> str:
    """
    For each failed file, call OpenAI to regenerate the diff segment
    using the actual file content as ground truth.
    """
    segments = _split_patch_segments(patch_text)
    result_segments = []

    for seg in segments:
        target = _extract_target_path(seg)

        if target not in failed_files:
            result_segments.append(seg)
            continue

        # Read actual file
        if not os.path.isfile(target):
            print(f"[self-heal] File not found for LLM regen: {target}")
            result_segments.append(seg)
            continue

        try:
            actual = pathlib.Path(target).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"[self-heal] Cannot read {target}: {e}")
            result_segments.append(seg)
            continue

        intent = _describe_diff_intent(seg)
        prompt = (
            f"ACTUAL FILE CONTENT of {target}:\n"
            f"```\n{actual}\n```\n\n"
            f"FAILED DIFF SEGMENT:\n"
            f"```\n{seg}\n```\n\n"
            f"INTENT OF THE CHANGE:\n{intent}\n\n"
            f"Produce a corrected unified diff for file: {target}\n"
            f"Use '--- a/{target}' and '+++ b/{target}' headers.\n"
            f"Context lines MUST exactly match the actual file content above."
        )

        print(f"[self-heal] Calling OpenAI to regenerate patch for: {target}")
        regen = _call_openai(prompt)

        if regen:
            regen = _sanitize(regen)
            regen = _html_unescape_recursive(regen)
            regen = _rewrite_patch_paths(regen, prefix)
            print(f"[self-heal] LLM regenerated patch for: {target}")
            result_segments.append(regen)
        else:
            print(f"[self-heal] LLM regen failed for {target}, keeping original")
            result_segments.append(seg)

    return _rejoin_segments(result_segments)


# ---------------------------------------------------------
#                    MAIN APPLY FLOW
# ---------------------------------------------------------

def ensure_branch_and_apply_diff(
    patch_path: pathlib.Path, module_prefix: Optional[str] = None
) -> str:
    """
    Create branch, rewrite patch, apply with self-healing.

    Apply strategy:
      1. Direct apply
      2. Fuzzy context repair (Unicode normalization) → retry
      3. LLM regeneration via OpenAI → retry
      4. Partial apply (--reject) as last resort
    """
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

    # 5) Validate patch structure
    warnings = _validate_patch(patched)
    if warnings:
        print("[patch-validation] Warnings found:")
        for w in warnings:
            print(f"  WARNING: {w}")

    # 6) Write final patch
    out = patch_path.with_suffix(".prefixed.diff")
    out.write_text(patched, encoding="utf-8")

    # 7) Show full patch
    run(f"echo '--- FINAL PATCH START ---'")
    run(f"wc -l {out}")
    run(f"cat {out}")
    run(f"echo '--- FINAL PATCH END ---'")

    # ── ATTEMPT 1: Direct apply ──────────────────────────
    print("\n[apply] ATTEMPT 1: Direct apply...")
    rc, err = run_capture(f"git apply --whitespace=fix -v {out}")
    if rc == 0:
        print("[apply] ✓ SUCCESS on first attempt.")
        return branch
    print(f"[apply] ✗ Attempt 1 failed (rc={rc}):\n{err}")

    # ── ATTEMPT 2: Fuzzy context repair ──────────────────
    print("\n[apply] ATTEMPT 2: Fuzzy context repair...")
    patched = _fuzzy_repair_patch(patched)
    out.write_text(patched, encoding="utf-8")

    run(f"echo '--- REPAIRED PATCH ---'")
    run(f"cat {out}")

    rc, err = run_capture(f"git apply --whitespace=fix -v {out}")
    if rc == 0:
        print("[apply] ✓ SUCCESS after fuzzy context repair.")
        return branch
    print(f"[apply] ✗ Attempt 2 failed (rc={rc}):\n{err}")

    # ── ATTEMPT 3: LLM regeneration ─────────────────────
    print("\n[apply] ATTEMPT 3: LLM regeneration...")
    failed_files = _parse_failed_files(err)
    if failed_files:
        print(f"[self-heal] Failed files: {failed_files}")
        patched = _llm_regenerate_failed_segments(patched, failed_files, prefix)
        out.write_text(patched, encoding="utf-8")

        run(f"echo '--- LLM-REGENERATED PATCH ---'")
        run(f"cat {out}")

        rc, err = run_capture(f"git apply --whitespace=fix -v {out}")
        if rc == 0:
            print("[apply] ✓ SUCCESS after LLM regeneration.")
            return branch
        print(f"[apply] ✗ Attempt 3 failed (rc={rc}):\n{err}")
    else:
        print("[self-heal] Could not parse failed files from error output.")

    # ── ATTEMPT 4: Partial apply (--reject) ──────────────
    print("\n[apply] ATTEMPT 4: Partial apply with --reject...")
    rc_rej, rej_out = run_capture(f"git apply --whitespace=fix --reject {out}")
    if rc_rej == 0:
        print("[apply] ✓ All hunks applied via --reject.")
        return branch

    # Even with --reject, some hunks may have applied
    rc_diff, diff_out = run_capture("git diff --stat")
    if diff_out.strip():
        print(f"[apply] Partial success — some hunks applied:\n{diff_out}")
        # Clean up .rej files
        run_capture("find . -name '*.rej' -delete 2>/dev/null")
        return branch

    raise RuntimeError(
        f"All 4 apply attempts failed. Last error:\n{err}\n"
        "Check the patch generators and actual file content."
    )


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
