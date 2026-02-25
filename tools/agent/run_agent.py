#!/usr/bin/env python3
import os
import sys
import json
import pathlib
import re
from typing import List, Set, Optional

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
from agent.utils.git_ops import (
    ensure_branch_and_apply_diff,
    open_pr,
    _rewrite_patch_paths,  # normalize git-style diff paths
)

# fixers
from agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker

OUTPUT = pathlib.Path(REPO_ROOT, "agent_output")
OUTPUT.mkdir(parents=True, exist_ok=True)

# --- Extraction helpers -------------------------------------------------------

def _extract_diff_segments(text: str) -> List[str]:
    """
    Extract valid diff segments without altering file paths.
    Only normalize EOLs. Do NOT unescape HTML or strip prefixes here.
    Accept:
      - git-style blocks starting with 'diff --git ' (must contain at least one '@@')
      - plain unified blocks starting with '--- <path>' then '+++ <path>' (must contain at least one '@@')
    """
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = t.split("\n")

    segs: List[str] = []
    i = 0
    n = len(lines)

    def has_hunk(seg: str) -> bool:
        return "@@" in seg

    def flush(start: int, end: int):
        seg = "\n".join(lines[start:end]).strip("\n")
        if seg and ("--- " in seg) and ("+++ " in seg) and has_hunk(seg):
            if not seg.endswith("\n"):
                seg += "\n"
            segs.append(seg)

    while i < n:
        line = lines[i]

        # git-style segment
        if line.startswith("diff --git "):
            s = i
            i += 1
            while i < n and not lines[i].startswith("diff --git "):
                i += 1
            flush(s, i)
            continue

        # plain unified segment
        if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            s = i
            i += 2
            while i < n and not (lines[i].startswith("--- ") or lines[i].startswith("diff --git ")):
                i += 1
            flush(s, i)
            continue

        i += 1

    return segs

HEADER_RE = re.compile(r"^(---|\+\+\+)\s+(\S+)(.*)$")

def _force_prefix_all_headers(segment: str, prefix: str) -> str:
    """
    Bulletproof header prefixing: rewrite ANY ---/+++ line
    including those with trailing metadata (tabs/timestamps).
    """
    out = []
    for line in segment.split("\n"):
        m = HEADER_RE.match(line)
        if not m:
            out.append(line)
            continue

        mark, path, meta = m.groups()
        # keep git-style a/ b/ intact; enforce on plain paths
        if not (path.startswith(prefix) or path.startswith("a/") or path.startswith("b/") or path.startswith("/") or path.startswith("./")):
            path = prefix + path

        out.append(f"{mark} {path}{meta}")
    return "\n".join(out)

def _html_unescape(text: str) -> str:
    """
    Unescape minimal HTML entities frequently seen in LLM outputs.
    IMPORTANT: apply after headers were fixed (so we don't alter paths).
    """
    # Order matters if inputs are double-encoded. Common case is single-encoded.
    t = text
    t = t.replace("&lt;", "<").replace("&gt;", ">")
    t = t.replace("&quot;", '"').replace("&#39;", "'")
    # Unescape '&' last to avoid turning &lt; into < prematurely
    t = t.replace("&amp;", "&")
    return t

def _rewrite_and_unescape_segment(segment: str, app_prefix: str) -> str:
    """
    Force APP_DIR prefix on plain headers, normalize git-style headers,
    then unescape HTML in the whole segment so body matches files.
    """
    seg = _force_prefix_all_headers(segment, app_prefix)
    seg = _rewrite_patch_paths(seg, app_prefix)
    seg = _html_unescape(seg)
    return seg if seg.endswith("\n") else seg + "\n"

def _target_file_from_segment(segment: str) -> Optional[str]:
    """
    Extract the target file path from the first '+++ ' header.
    Return a normalized path without leading a/ or b/.
    """
    for line in segment.split("\n"):
        if line.startswith("+++ "):
            p = line[4:].strip()
            # Strip trailing metadata after a tab, if present
            if "\t" in p:
                p = p.split("\t", 1)[0]
            # Strip Git-style prefixes
            if p.startswith("a/") or p.startswith("b/"):
                p = p[2:]
            return p
    return None

def _append_candidate(container: List[str], candidate: str, app_prefix: str, seen_paths: Set[str]):
    segs = _extract_diff_segments(candidate)
    if not segs:
        return

    for s in segs:
        normalized = _rewrite_and_unescape_segment(s, app_prefix)
        # De-duplicate per target file to avoid conflicting hunks (e.g., multiple pom.xml changes)
        target = _target_file_from_segment(normalized)
        if target and target in seen_paths:
            continue
        if normalized not in container:
            container.append(normalized)
            if target:
                seen_paths.add(target)

# --- Orchestration ------------------------------------------------------------

def handle_findings(kind: str, items: list, retriever: RepoRetriever, diffs: list, app_prefix: str, seen_paths: Set[str]):
    if not items:
        return

    fixers = {
        "k8s": fixer_k8s,
        "tf": fixer_tf,
        "java": fixer_java,
        "docker": fixer_docker,
    }
    fx = fixers[kind]

    for it in items:
        # 1) Deterministic
        d = fx.try_deterministic(it)
        if d:
            log_topk(kind, it, query="(deterministic)", topk=[], mode="deterministic")
            _append_candidate(diffs, d, app_prefix, seen_paths)
            continue

        # 2) RAG (repo-aware)
        q = fx.query_for(it)
        topk = retriever.search(q) if q else []
        d = fx.try_rag_style(it, topk)
        if d:
            log_topk(kind, it, query=q, topk=topk, mode="rag")
            _append_candidate(diffs, d, app_prefix, seen_paths)
            continue

        # 3) Trained-knowledge fallback (LLM prompt → diff)
        log_topk(kind, it, query=q or "(no-query)", topk=topk, mode="trained")
        prompt = build_patch_prompt(kind, it, topk)
        d = call_llm_for_diff(prompt)
        _append_candidate(diffs, d, app_prefix, seen_paths)

def main():
    app_prefix = (os.getenv("APP_DIR") or "java-pilot-app").rstrip("/") + "/"

    min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
    findings = get_findings(min_sev)
    retriever = RepoRetriever(top_k=6)
    diffs: List[str] = []
    seen_paths: Set[str] = set()

    handle_findings("k8s", findings.get("k8s", []), retriever, diffs, app_prefix, seen_paths)
    handle_findings("tf", findings.get("tf", []), retriever, diffs, app_prefix, seen_paths)
    handle_findings("java", findings.get("java", []), retriever, diffs, app_prefix, seen_paths)
    handle_findings("docker", findings.get("docker", []), retriever, diffs, app_prefix, seen_paths)

    if not diffs:
        print("Agent generated no diffs; exiting.")
        return

    # Join with a blank line between segments
    patch = OUTPUT / "agent_patch.diff"
    patch.write_text("\n\n".join(diffs), encoding="utf-8")

    # Apply the rewritten patch once and open a PR
    br = ensure_branch_and_apply_diff(patch)
    pr = open_pr(br, "Agentic AI autofix (deterministic→RAG→trained)", f"Threshold: {min_sev}\nAutomated minimal diffs.")
    print(f"Branch: {br}\nPR: {pr}")

if __name__ == "__main__":
    main()