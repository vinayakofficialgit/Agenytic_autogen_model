#!/usr/bin/env python3
import os
import sys
import json
import shutil
import tempfile
import subprocess
import pathlib
from typing import List, Tuple

# ── Make 'tools/' the package root so 'agent' and 'embeddings' imports work ──
HERE = pathlib.Path(__file__).resolve()
TOOLS_ROOT = HERE.parents[1]  # .../tools
REPO_ROOT = HERE.parents[2]   # repo root
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from agent.utils.debug import log_topk
from embeddings.retriever import RepoRetriever
from agent.pick_findings import get_findings
from agent.utils.prompt_lib import build_patch_prompt, call_llm_for_diff
# reuse sanitizers/rewriter for consistent behavior
# from agent.utils.git_ops import (
#     ensure_branch_and_apply_diff,
#     open_pr,
#     _sanitize_patch as sanitize_patch_text,
#     _rewrite_patch_paths,
# )
from agent.utils.git_ops import (
    ensure_branch_and_apply_diff,
    open_pr,
    _rewrite_patch_paths,     # KEEP
)
# DO NOT IMPORT sanitize_patch_text

# fixers
from agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker

OUTPUT = pathlib.Path(REPO_ROOT, "agent_output")
OUTPUT.mkdir(parents=True, exist_ok=True)

def _extract_diff_segments(text: str) -> List[str]:
    """
    Extract valid diff segments without altering file paths.
    Only normalize EOLs. Do NOT sanitize file paths.
    """
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = t.split("\n")

    segs = []
    i = 0
    n = len(lines)

    def has_hunk_markers(block: str) -> bool:
        return "@@" in block

    def flush(start, end):
        seg = "\n".join(lines[start:end]).strip("\n")
        if seg and "--- " in seg and "+++ " in seg and has_hunk_markers(seg):
            if not seg.endswith("\n"):
                seg += "\n"
            segs.append(seg)

    while i < n:
        line = lines[i]

        # git-style
        if line.startswith("diff --git "):
            start = i
            i += 1
            while i < n and not lines[i].startswith("diff --git "):
                i += 1
            flush(start, i)
            continue

        # unified
        if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            start = i
            i += 2
            while i < n and not (
                lines[i].startswith("--- ") or lines[i].startswith("diff --git ")
            ):
                i += 1
            flush(start, i)
            continue

        i += 1

    return segs

# def _extract_diff_segments(text: str) -> List[str]:
#     """
#     Extract only valid diff segments from arbitrary text, in order.
#     We accept:
#       - git-style blocks starting with 'diff --git ' (and containing at least one '@@')
#       - plain unified blocks starting with '--- <path>' then '+++ <path>' (with at least one '@@')
#     All other text is dropped.
#     """
#     # First sanitize: normalize EOLs, drop code fences, unescape HTML
#     # t = sanitize_patch_text(text)
#     t = text.replace("\r\n", "\n").replace("\r", "\n")
#     # DO NOT UNESCAPE HTML HERE
#     lines = t.split("\n")
#     segs: List[str] = []
#     i, n = 0, len(lines)

#     def has_hunk_markers(block: str) -> bool:
#         # Minimal validity check: unified hunks must contain at least one '@@'
#         return "@@ " in block

#     def flush(start: int, end: int):
#         seg = "\n".join(lines[start:end]).strip("\n")
#         if seg and ("--- " in seg) and ("+++ " in seg) and has_hunk_markers(seg):
#             if not seg.endswith("\n"):
#                 seg += "\n"
#             segs.append(seg)

#     while i < n:
#         line = lines[i]

#         # Case 1: git-style segment
#         if line.startswith("diff --git "):
#             start = i
#             i += 1
#             # consume until next git-style header or EOF
#             while i < n and not lines[i].startswith("diff --git "):
#                 i += 1
#             flush(start, i)
#             continue

#         # Case 2: plain unified '--- ' then '+++ '
#         if line.startswith("--- ") and (i + 1 < n) and lines[i + 1].startswith("+++ "):
#             start = i
#             i += 2
#             # consume until next '--- ' or 'diff --git ' or EOF
#             while i < n and not (lines[i].startswith("--- ") or lines[i].startswith("diff --git ")):
#                 i += 1
#             flush(start, i)
#             continue

#         # otherwise skip
#         i += 1

#     return segs




def _git_apply_check(segment_text: str, prefix: str | None = None) -> Tuple[bool, str]:
    """
    Write the segment to a temp file and run 'git apply --check'.
    If prefix is provided, rewrite paths before checking.
    Returns (ok, possibly_rewritten_segment_text).
    """
    seg = segment_text

    # ALWAYS enforce prefix normalization first
    enforced = []
    for line in seg.split("\n"):
        if line.startswith("--- "):
            path = line[4:].strip()
            if not path.startswith(prefix):
                line = "--- " + prefix + path
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if not path.startswith(prefix):
                line = "+++ " + prefix + path
        enforced.append(line)

    seg = "\n".join(enforced)

    # Now optionally try rewrite using the advanced path rewriter
    if prefix:
        seg = _rewrite_patch_paths(seg, prefix)

    # Write to temp file
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".diff", encoding="utf-8") as tf:
        tf.write(seg)
        tf.flush()
        tmp_path = tf.name

    try:
        subprocess.check_call(f"git apply --check {tmp_path}", shell=True, cwd=REPO_ROOT)
        ok = True
    except subprocess.CalledProcessError:
        ok = False
    finally:
        os.unlink(tmp_path)

    return ok, seg


def _validate_and_collect(segments: List[str]) -> List[str]:
    """
    Keep only segments that pass 'git apply --check' after mandatory prefixing.
    Deduplicate segments.
    """
    prefix = (os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"
    kept: List[str] = []
    seen = set()

    for seg in segments:
        ok, fixed_seg = _git_apply_check(seg, prefix=prefix)
        if ok:
            if fixed_seg not in seen:
                kept.append(fixed_seg.rstrip("\n") + "\n")
                seen.add(fixed_seg)

    return kept

# def _git_apply_check(segment_text: str, prefix: str | None = None) -> Tuple[bool, str]:
#     """
#     Write the segment to a temp file and run 'git apply --check'.
#     If prefix is provided, rewrite paths before checking.
#     Returns (ok, possibly_rewritten_segment_text).
#     """
#     seg = segment_text
#     if prefix:
#         seg = _rewrite_patch_paths(seg, prefix)

#     with tempfile.NamedTemporaryFile("w", delete=False, suffix=".diff", encoding="utf-8") as tf:
#         tf.write(seg)
#         tf.flush()
#         tmp_path = tf.name

#     try:
#         subprocess.check_call(f"git apply --check {tmp_path}", shell=True, cwd=REPO_ROOT)
#         ok = True
#     except subprocess.CalledProcessError:
#         ok = False
#     finally:
#         try:
#             os.unlink(tmp_path)
#         except Exception:
#             pass

#     return ok, seg


# def _validate_and_collect(segments: List[str]) -> List[str]:
#     """
#     Keep only segments that pass 'git apply --check' as-is OR with module prefix.
#     Deduplicate segments (exact text) to avoid repetitions.
#     """
#     prefix = (os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"
#     kept: List[str] = []
#     seen = set()

#     for seg in segments:
#         # Try as-is
#         ok, use_seg = _git_apply_check(seg, prefix=None)
#         if not ok:
#             # Try with module prefix
#             ok, use_seg = _git_apply_check(seg, prefix=prefix)
#         if ok:
#             if use_seg not in seen:
#                 kept.append(use_seg.rstrip("\n") + "\n")
#                 seen.add(use_seg)
#         else:
#             # Drop invalid segment silently; it's not safe to apply.
#             pass

#     return kept


def _append_candidate(container: List[str], candidate: str):
    """Extract → validate → collect segments from candidate."""
    segs = _extract_diff_segments(candidate)
    valid = _validate_and_collect(segs)
    container.extend(valid)


def handle_findings(kind: str, items: list, retriever: RepoRetriever, diffs: list):
    if not items:
        return

    fx_map = {
        "k8s": fixer_k8s,
        "tf": fixer_tf,
        "java": fixer_java,
        "docker": fixer_docker,
    }
    fx = fx_map[kind]

    for it in items:
        # 1) Deterministic
        d = fx.try_deterministic(it)
        if d:
            log_topk(kind, it, query="(deterministic)", topk=[], mode="deterministic")
            _append_candidate(diffs, d)
            continue

        # 2) RAG (repo-aware)
        q = fx.query_for(it)
        topk = retriever.search(q) if q else []
        d = fx.try_rag_style(it, topk)
        if d:
            log_topk(kind, it, query=q, topk=topk, mode="rag")
            _append_candidate(diffs, d)
            continue

        # 3) Trained-knowledge fallback (LLM prompt → diff)
        # NOTE: We'll only keep it if it survives segment validation.
        log_topk(kind, it, query=q or "(no-query)", topk=topk, mode="trained")
        prompt = build_patch_prompt(kind, it, topk)
        d = call_llm_for_diff(prompt)
        _append_candidate(diffs, d)


def main():
    min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
    findings = get_findings(min_sev)
    retriever = RepoRetriever(top_k=6)
    diffs: List[str] = []

    handle_findings("k8s", findings.get("k8s", []), retriever, diffs)
    handle_findings("tf", findings.get("tf", []), retriever, diffs)
    handle_findings("java", findings.get("java", []), retriever, diffs)
    handle_findings("docker", findings.get("docker", []), retriever, diffs)

    if not diffs:
        print("Agent generated no diffs; exiting.")
        return

    # Join with blank line between segments
    patch = OUTPUT / "agent_patch.diff"
    patch.write_text("\n\n".join(diffs), encoding="utf-8")

    # Apply diff on a new AI branch and open a PR
    br = ensure_branch_and_apply_diff(patch)
    pr = open_pr(br, "Agentic AI autofix (deterministic→RAG→trained)", f"Threshold: {min_sev}\nAutomated minimal diffs.")

    # Save PR meta so workflow can comment reliably
    (OUTPUT / "agent_meta.json").write_text(
        json.dumps({"branch": br, "pr_url": pr}, indent=2),
        encoding="utf-8",
    )
    print(f"Branch: {br}\nPR: {pr}")


if __name__ == "__main__":
    main()