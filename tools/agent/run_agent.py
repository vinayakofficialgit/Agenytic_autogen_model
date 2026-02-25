#!/usr/bin/env python3
import os
import sys
import json
import pathlib
from typing import List

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


def _sanitize_text(text: str) -> str:
    """Remove markdown fences, unescape HTML, normalize EOLs to LF."""
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    # Drop lines that are just code fences (``` or ```lang)
    lines = []
    for line in t.split("\n"):
        if line.strip().startswith("```"):
            continue
        lines.append(line)
    t = "\n".join(lines)
    # Basic HTML unescape sufficient for our content
    t = t.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return t


def _extract_diff_segments(text: str) -> List[str]:
    """
    Extract only valid diff segments from text, in order.
      - git-style blocks that start with 'diff --git' (kept verbatim)
      - plain unified blocks that start with '--- <path>' then '+++ <path>'
    All other text is discarded.
    """
    t = _sanitize_text(text)
    lines = t.split("\n")
    segs: List[str] = []
    i = 0
    n = len(lines)

    def flush_segment(start: int, end: int):
        seg = "\n".join(lines[start:end]).strip("\n")
        if seg:
            # minimal validity check: must contain both headers
            if ("--- " in seg) and ("+++ " in seg):
                if not seg.endswith("\n"):
                    seg += "\n"
                segs.append(seg)

    while i < n:
        line = lines[i]

        # Case 1: git-style segment
        if line.startswith("diff --git "):
            start = i
            i += 1
            # consume until next 'diff --git ' or EOF
            while i < n and not lines[i].startswith("diff --git "):
                i += 1
            flush_segment(start, i)
            continue

        # Case 2: plain unified segment '--- <path>' followed by '+++ <path>'
        if line.startswith("--- ") and (i + 1 < n) and lines[i + 1].startswith("+++ "):
            start = i
            i += 2
            # consume until next segment start (--- or diff --git) or EOF
            while i < n and not (
                lines[i].startswith("--- ") or lines[i].startswith("diff --git ")
            ):
                i += 1
            flush_segment(start, i)
            continue

        # Otherwise skip noise line
        i += 1

    return segs


def _append_candidate(container: List[str], candidate: str):
    """Extract segments from candidate and append them to container."""
    for seg in _extract_diff_segments(candidate):
        container.append(seg)


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