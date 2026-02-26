#!/usr/bin/env python3
"""
run_agent.py — Main orchestrator for agentic AI autofix pipeline.

Flow:
  1. Load security findings (Semgrep, Trivy, tfsec, etc.)
  2. For each finding category, attempt fixes in order:
       a) Deterministic (regex-based)
       b) RAG (repo-context-aware)
       c) LLM fallback (OpenAI prompt → diff)
  3. Combine all diffs, apply as a single patch, commit, and open a PR.
"""
import os
import sys
import json
import pathlib
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
from agent.utils.git_ops import ensure_branch_and_apply_diff, open_pr

# fixers
from agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker

OUTPUT = pathlib.Path(REPO_ROOT, "agent_output")
OUTPUT.mkdir(parents=True, exist_ok=True)


def _extract_diff_segments(text: str) -> List[str]:
    """
    Extract valid diff segments without altering file paths.
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
            while i < n and not (
                lines[i].startswith("--- ") or lines[i].startswith("diff --git ")
            ):
                i += 1
            flush(s, i)
            continue

        i += 1

    return segs


def _target_file_from_segment(segment: str) -> Optional[str]:
    """
    Extract the target file path from the first '+++ ' header.
    Return a normalized path without leading a/ or b/.
    """
    for line in segment.split("\n"):
        if line.startswith("+++ "):
            p = line[4:].strip()
            if "\t" in p:
                p = p.split("\t", 1)[0]
            if p.startswith("a/") or p.startswith("b/"):
                p = p[2:]
            return p
    return None


def _append_candidate(container: List[str], candidate: str, seen_paths: Set[str]):
    """Append unique diff segments, de-duplicating by target file."""
    segs = _extract_diff_segments(candidate)
    if not segs:
        print(f"  [pipeline] WARNING: No valid diff segments extracted from candidate ({len(candidate)} chars)")
        return
    for s in segs:
        target = _target_file_from_segment(s)
        if target and target in seen_paths:
            print(f"  [pipeline] Skipping duplicate target: {target}")
            continue
        if s not in container:
            container.append(s if s.endswith("\n") else s + "\n")
            if target:
                seen_paths.add(target)
                print(f"  [pipeline] Added diff segment for: {target}")


def handle_findings(kind: str, items: list, retriever: RepoRetriever, diffs: list, seen_paths: Set[str]):
    """Process findings of a given kind through the 3-tier fix strategy."""
    if not items:
        return

    print(f"\n{'='*60}")
    print(f"[{kind}] Processing {len(items)} finding(s)...")
    print(f"{'='*60}")

    fx_map = {
        "k8s": fixer_k8s,
        "tf": fixer_tf,
        "java": fixer_java,
        "docker": fixer_docker,
    }
    fx = fx_map[kind]

    for idx, it in enumerate(items):
        print(f"\n[{kind}] Finding {idx+1}/{len(items)}: {it.get('file', 'unknown')}")

        # 1) Deterministic (regex-based, fastest)
        d = fx.try_deterministic(it)
        if d:
            log_topk(kind, it, query="(deterministic)", topk=[], mode="deterministic")
            print(f"  [pipeline] ✓ Deterministic fix generated ({len(d)} chars)")
            _append_candidate(diffs, d, seen_paths)
            continue

        # 2) RAG (repo-context-aware)
        q = fx.query_for(it)
        topk = retriever.search(q) if q else []
        d = fx.try_rag_style(it, topk)
        if d:
            log_topk(kind, it, query=q, topk=topk, mode="rag")
            print(f"  [pipeline] ✓ RAG fix generated ({len(d)} chars)")
            _append_candidate(diffs, d, seen_paths)
            continue

        # 3) LLM fallback (OpenAI prompt → diff)
        log_topk(kind, it, query=q or "(no-query)", topk=topk, mode="trained")
        prompt = build_patch_prompt(kind, it, topk)
        d = call_llm_for_diff(prompt)
        if d:
            print(f"  [pipeline] ✓ LLM fix generated ({len(d)} chars)")
            _append_candidate(diffs, d, seen_paths)
        else:
            print(f"  [pipeline] ✗ All 3 fix strategies failed for this finding")


def main():
    min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
    print(f"\n{'#'*60}")
    print(f"# Agentic AI Autofix Pipeline")
    print(f"# MIN_SEVERITY = {min_sev}")
    print(f"# CWD = {os.getcwd()}")
    print(f"# REPO_ROOT = {REPO_ROOT}")
    print(f"{'#'*60}\n")

    findings = get_findings(min_sev)

    # Log what findings we got
    for kind, items in findings.items():
        if items:
            print(f"[findings] {kind}: {len(items)} finding(s)")
            for it in items:
                print(f"  - {it.get('file', 'unknown')}: {it.get('check_id', it.get('rule', 'unknown'))}")

    retriever = RepoRetriever(top_k=6)
    diffs: List[str] = []
    seen_paths: Set[str] = set()

    handle_findings("k8s", findings.get("k8s", []), retriever, diffs, seen_paths)
    handle_findings("tf", findings.get("tf", []), retriever, diffs, seen_paths)
    handle_findings("java", findings.get("java", []), retriever, diffs, seen_paths)
    handle_findings("docker", findings.get("docker", []), retriever, diffs, seen_paths)

    print(f"\n{'='*60}")
    print(f"[pipeline] Total diff segments generated: {len(diffs)}")
    print(f"[pipeline] Target files: {sorted(seen_paths)}")
    print(f"{'='*60}")

    if not diffs:
        print("Agent generated no diffs; exiting.")
        return

    # Join with a blank line between segments
    patch = OUTPUT / "agent_patch.diff"
    combined = "\n\n".join(diffs)
    patch.write_text(combined, encoding="utf-8")
    print(f"[pipeline] Wrote combined patch: {patch} ({len(combined)} chars)")

    # Apply the rewritten patch, commit, and open a PR
    br = ensure_branch_and_apply_diff(patch)
    pr = open_pr(br, "Agentic AI autofix (deterministic→RAG→trained)", f"Threshold: {min_sev}\nAutomated minimal diffs.")
    print(f"\n{'='*60}")
    print(f"[DONE] Branch: {br}")
    print(f"[DONE] PR: {pr}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
