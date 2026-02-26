#!/usr/bin/env python3
"""
git_ops.py — Branch creation, patch rewriting, self-healing apply, commit & push.

Self-healing strategy when `git apply` fails:
  1. Fuzzy context repair: read the actual file, fix context lines
     in the patch that differ only by Unicode or whitespace.
  2. LLM regeneration: call OpenAI to produce a corrected diff
     using the real file content as ground truth.
  3. Partial apply (--reject) as last resort.

After successful apply, changes are staged, committed, and pushed
so the PR branch actually contains the modifications.
"""
import subprocess
import time
import os
import pathlib
import re
import html
import json
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
    print(output)
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


def _commit_and_verify(message: str) -> bool:
    """
    Stage ALL changes, commit, and verify the commit contains modified files.
    Returns True if commit succeeded with actual changes.
    """
    print("\n[commit] Staging and committing changes...")

    # Stage all changes
    rc_add, add_out = run_capture("git add -A")
    if rc_add != 0:
        print(f"[commit] ERROR: git add failed: {add_out}")
        return False

    # Show what's staged (this is the key diagnostic)
    rc_status, status_out = run_capture("git status --short")
    print(f"[commit] Staged files:\n{status_out}")

    if not status_out.strip():
        print("[commit] WARNING: Nothing staged — git apply may not have changed any files!")

        # Extra diagnostic: check if working tree has any changes at all
        rc_diff, diff_out = run_capture("git diff --name-only")
        print(f"[commit] Unstaged changes: {diff_out}")
        rc_diff2, diff_out2 = run_capture("git diff --cached --name-only")
        print(f"[commit] Cached changes: {diff_out2}")
        return False

    # Commit
    rc_commit, commit_out = run_capture(f'git commit -m "{message}"')
    if rc_commit != 0:
        if "nothing to commit" in commit_out:
            print("[commit] WARNING: nothing to commit.")
            return False
        print(f"[commit] ERROR: git commit failed: {commit_out}")
        return False

    # Verify: show what the commit contains
    print("[commit] ✓ Commit created. Verifying contents...")
    rc_show, show_out = run_capture("git log --oneline -1")
    print(f"[commit] Latest commit: {show_out.strip()}")
    rc_show2, show_out2 = run_capture("git diff --stat HEAD~1 HEAD")
    print(f"[commit] Commit diff stat:\n{show_out2}")

    # Double check: show the actual file diff to confirm changes
    rc_show3, show_out3 = run_capture("git diff HEAD~1 HEAD")
    if show_out3.strip():
        print(f"[commit] Commit diff preview (first 2000 chars):\n{show_out3[:2000]}")
    else:
        print("[commit] WARNING: Commit appears empty!")
        return False

    return True


# ---------------------------------------------------------
#               SAFE, GLOBAL TRANSFORMS
# ---------------------------------------------------------

def _sanitize(text: str) -> str:
    """Normalize EOLs and remove markdown ``` lines."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"^\s*`{3,}.*$", "", text, flags=re.M)


def _html_unescape_recursive(text: str) -> str:
    """Fully unescape HTML entities so diff hunks match repo files."""
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
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _ensure_prefix(path: str, prefix: str) -> str:
    if path.startswith(prefix) or path.startswith("/") or path.startswith("./"):
        return path
    return prefix + path


def _normalize_header(line: str, prefix: str) -> str:
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
    m = _DIFF_GIT_RE.match(line)
    if not m:
        return line
    a_path, b_path = m.groups()
    a_path = _ensure_prefix(a_path, prefix)
    b_path = _ensure_prefix(b_path, prefix)
    return f"diff --git a/{a_path} b/{b_path}"


def _extract_path_from_header(line: str) -> str:
    path = line[4:].strip()
    if "\t" in path:
        path = path.split("\t", 1)[0]
    return _strip_ab(path)


def _rewrite_patch_paths(text: str, prefix: str) -> str:
    """
    Normalize ALL headers across the patch and ensure every segment
    has a proper 'diff --git a/... b/...' header line.

    CRITICAL: The seen_diff_git flag is ONLY reset when we reach a
    '--- ' line. Intermediate lines like 'index ...', 'old mode ...'
    appear between 'diff --git' and '---' and must NOT reset the flag.
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

_UNICODE_TO_ASCII = {
    "\u2011": "-",   # non-breaking hyphen
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
    for uc, asc in _UNICODE_TO_ASCII.items():
        text = text.replace(uc, asc)
    return text


def _fuzzy_line_match(patch_line: str, file_line: str) -> bool:
    a = _normalize_unicode(patch_line).rstrip()
    b = _normalize_unicode(file_line).rstrip()
    if a == b:
        return True
    if a.strip() == b.strip():
        return True
    return False


def _extract_target_path(segment: str) -> Optional[str]:
    for line in segment.split("\n"):
        if line.startswith("+++ "):
            p = line[4:].strip()
            if "\t" in p:
                p = p.split("\t", 1)[0]
            return _strip_ab(p)
    return None


def _split_patch_segments(patch_text: str) -> List[str]:
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
    return "\n".join(s.rstrip("\n") for s in segments) + "\n"


def _repair_context_lines(segment: str, file_content: str) -> str:
    file_lines = file_content.split("\n")
    patch_lines = segment.split("\n")
    result = []
    hunk_re = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")
    file_idx = 0
    in_hunk = False

    for pl in patch_lines:
        hm = hunk_re.match(pl)
        if hm:
            file_idx = int(hm.group(1)) - 1
            in_hunk = True
            result.append(pl)
            continue

        if not in_hunk:
            result.append(pl)
            continue

        if pl.startswith(" "):
            if 0 <= file_idx < len(file_lines):
                actual = file_lines[file_idx]
                patch_content = pl[1:]
                if patch_content.rstrip() != actual.rstrip():
                    if _fuzzy_line_match(patch_content, actual):
                        print(f"  [fuzzy-fix] line {file_idx+1}: "
                              f"'{patch_content.strip()[:50]}' → '{actual.strip()[:50]}'")
                        pl = " " + actual
            file_idx += 1
        elif pl.startswith("-"):
            if 0 <= file_idx < len(file_lines):
                actual = file_lines[file_idx]
                patch_content = pl[1:]
                if patch_content.rstrip() != actual.rstrip():
                    if _fuzzy_line_match(patch_content, actual):
                        print(f"  [fuzzy-fix] line {file_idx+1}: "
                              f"'{patch_content.strip()[:50]}' → '{actual.strip()[:50]}'")
                        pl = "-" + actual
            file_idx += 1
        elif pl.startswith("+"):
            pass

        result.append(pl)

    return "\n".join(result)


def _fuzzy_repair_patch(patch_text: str) -> str:
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
        url, data=payload,
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
    failed = []
    for m in re.finditer(r"error: patch failed: ([^:]+):", error_output):
        path = m.group(1).strip()
        if path not in failed:
            failed.append(path)
    return failed


def _describe_diff_intent(segment: str) -> str:
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
    segments = _split_patch_segments(patch_text)
    result_segments = []

    for seg in segments:
        target = _extract_target_path(seg)
        if target not in failed_files:
            result_segments.append(seg)
            continue

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
    Create branch, rewrite patch, apply with self-healing, COMMIT and PUSH.

    Apply strategy (tries each, stops on first success):
      1. Direct apply
      2. Fuzzy context repair (Unicode normalization) → retry
      3. LLM regeneration via OpenAI → retry
      4. Partial apply (--reject) as last resort

    After successful apply: git add -A → git commit → verified.
    """
    ensure_git_identity()

    branch = f"ai-autofix-{int(time.time())}"
    run(f"git checkout -b {branch}")

    prefix = (module_prefix or os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"
    print(f"[config] module prefix = '{prefix}'")
    print(f"[config] CWD = {os.getcwd()}")

    # 1) Load raw patch
    raw = pathlib.Path(patch_path).read_text(encoding="utf-8", errors="ignore")
    print(f"[patch] Raw patch: {len(raw)} chars, {raw.count(chr(10))} lines")

    # 2) Sanitize markdown + normalize EOLs
    patched = _sanitize(raw)

    # 3) Rewrite ALL headers (plain unified → proper git-style a/b)
    patched = _rewrite_patch_paths(patched, prefix)

    # 4) Fully unescape HTML
    before_lt = patched.count("&lt;")
    before_gt = patched.count("&gt;")
    patched = _html_unescape_recursive(patched)
    after_lt = patched.count("&lt;")
    after_gt = patched.count("&gt;")

    print(f"[patch-info] &lt; count: {before_lt} -> {after_lt} ; &gt; count: {before_gt} -> {after_gt}")

    if after_lt or after_gt:
        final_preview = (patched[:4000] + "...\n") if len(patched) > 4000 else patched
        raise RuntimeError(
            "HTML entities remain in patch after unescape. Preview:\n" + final_preview
        )

    # 5) Validate
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
    print("\n" + "="*60)
    print("[apply] ATTEMPT 1: Direct apply...")
    print("="*60)
    rc, err = run_capture(f"git apply --whitespace=fix -v {out}")
    if rc == 0:
        print("[apply] ✓ SUCCESS on first attempt.")
        committed = _commit_and_verify("AI autofix: automated security remediation")
        if committed:
            return branch
        print("[apply] WARNING: Apply reported success but no changes committed!")

    print(f"[apply] ✗ Attempt 1 failed (rc={rc})")

    # ── ATTEMPT 2: Fuzzy context repair ──────────────────
    print("\n" + "="*60)
    print("[apply] ATTEMPT 2: Fuzzy context repair...")
    print("="*60)
    patched = _fuzzy_repair_patch(patched)
    out.write_text(patched, encoding="utf-8")

    run(f"echo '--- REPAIRED PATCH ---'")
    run(f"cat {out}")

    rc, err = run_capture(f"git apply --whitespace=fix -v {out}")
    if rc == 0:
        print("[apply] ✓ SUCCESS after fuzzy context repair.")
        committed = _commit_and_verify("AI autofix: security remediation (fuzzy-repaired)")
        if committed:
            return branch
        print("[apply] WARNING: Apply reported success but no changes committed!")

    print(f"[apply] ✗ Attempt 2 failed (rc={rc})")

    # ── ATTEMPT 3: LLM regeneration ─────────────────────
    print("\n" + "="*60)
    print("[apply] ATTEMPT 3: LLM regeneration...")
    print("="*60)
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
            committed = _commit_and_verify("AI autofix: security remediation (LLM-regenerated)")
            if committed:
                return branch
            print("[apply] WARNING: Apply reported success but no changes committed!")

        print(f"[apply] ✗ Attempt 3 failed (rc={rc})")
    else:
        print("[self-heal] Could not parse failed files from error output.")

    # ── ATTEMPT 4: Partial apply (--reject) ──────────────
    print("\n" + "="*60)
    print("[apply] ATTEMPT 4: Partial apply with --reject...")
    print("="*60)
    rc_rej, rej_out = run_capture(f"git apply --whitespace=fix --reject {out}")

    # Check if any changes exist (even partial)
    rc_diff, diff_out = run_capture("git diff --name-only")
    if diff_out.strip():
        print(f"[apply] Partial success — modified files:\n{diff_out}")
        run_capture("find . -name '*.rej' -delete 2>/dev/null")
        committed = _commit_and_verify("AI autofix: partial security remediation")
        if committed:
            return branch

    raise RuntimeError(
        f"All 4 apply attempts failed. Last error:\n{err}\n"
        "Check the patch generators and actual file content."
    )


def open_pr(branch: str, title: str, body: str) -> str:
    """Push branch and open PR via gh CLI."""
    # Push the branch first
    print(f"\n[pr] Pushing branch '{branch}' to origin...")
    rc, push_out = run_capture(f"git push origin {branch}")
    if rc != 0:
        print(f"[pr] WARNING: git push failed: {push_out}")
        print("[pr] Attempting gh pr create (it may auto-push)...")

    try:
        out = subprocess.check_output(
            f'gh pr create --title "{title}" --body "{body}" --head "{branch}"',
            shell=True, stderr=subprocess.STDOUT
        ).decode()
        return out.strip()
    except Exception as e:
        print(f"gh failed: {e}")
        return "(install gh to auto-open PR)"
