#!/usr/bin/env python3
import os
import sys
import json
import pathlib
import subprocess
from typing import List, Set

HERE = pathlib.Path(__file__).resolve()
TOOLS_ROOT = HERE.parents[1]
REPO_ROOT = HERE.parents[2]

if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from embeddings.retriever import RepoRetriever
from agent.pick_findings import get_findings
from agent.utils.prompt_lib import build_patch_prompt, call_llm_for_diff
from agent.utils.git_ops import ensure_branch_and_apply_diff
from agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker

OUTPUT = pathlib.Path(REPO_ROOT, "agent_output")
OUTPUT.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# STRICT DIFF VALIDATION
# ---------------------------------------------------------

def is_valid_unified_diff(text: str) -> bool:
    """
    Validate minimal unified diff structure.
    """
    if not text:
        return False
    if not text.startswith("--- "):
        return False
    if "+++ " not in text:
        return False
    if "@@" not in text:
        return False
    return True


def extract_valid_segments(text: str) -> List[str]:
    """
    Split multiple diffs and keep only structurally valid ones.
    """
    segments = []
    blocks = text.split("\ndiff --git ")

    for i, block in enumerate(blocks):
        if i > 0:
            block = "diff --git " + block
        block = block.strip()
        if is_valid_unified_diff(block):
            segments.append(block)

    return segments


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    try:
        min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
        findings = get_findings(min_sev)

        retriever = RepoRetriever(top_k=6)

        diffs: List[str] = []
        seen_paths: Set[str] = set()

        def handle(kind, items):
            fx_map = {
                "k8s": fixer_k8s,
                "tf": fixer_tf,
                "java": fixer_java,
                "docker": fixer_docker,
            }
            fx = fx_map[kind]

            for it in items:

                # 1️⃣ Deterministic
                d = fx.try_deterministic(it)
                if is_valid_unified_diff(d):
                    diffs.append(d)
                    continue

                # 2️⃣ RAG
                q = fx.query_for(it)
                topk = retriever.search(q) if q else []
                d = fx.try_rag_style(it, topk)
                if is_valid_unified_diff(d):
                    diffs.append(d)
                    continue

                # 3️⃣ LLM fallback
                prompt = build_patch_prompt(kind, it, topk)
                d = call_llm_for_diff(prompt)

                if not d:
                    continue

                segments = extract_valid_segments(d)

                for seg in segments:
                    diffs.append(seg)

        handle("k8s", findings.get("k8s", []))
        handle("tf", findings.get("tf", []))
        handle("java", findings.get("java", []))
        handle("docker", findings.get("docker", []))

        if not diffs:
            print("⚠ No valid diffs generated. Skipping branch creation.")
            return

        # Write combined patch
        patch = OUTPUT / "agent_patch.diff"
        patch.write_text("\n\n".join(diffs), encoding="utf-8")

        # 🔥 Validate BEFORE branch creation
        try:
            subprocess.check_call(
                f"git apply --check {patch}",
                shell=True
            )
        except subprocess.CalledProcessError:
            print("⚠ Generated patch is invalid. Skipping branch creation.")
            return

        # Apply + push branch
        branch = ensure_branch_and_apply_diff(patch)

        meta = OUTPUT / "agent_meta.json"
        meta.write_text(json.dumps({"branch": branch}), encoding="utf-8")

        print(f"✅ Branch created: {branch}")

    except Exception as e:
        print(f"Agent failed safely: {e}")
        sys.exit(0)


if __name__ == "__main__":
    main()