#!/usr/bin/env python3
import os
import sys
import json
import pathlib
from typing import List, Set, Optional

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
                d = fx.try_deterministic(it)
                if d:
                    diffs.append(d)
                    continue

                q = fx.query_for(it)
                topk = retriever.search(q) if q else []

                d = fx.try_rag_style(it, topk)
                if d:
                    diffs.append(d)
                    continue

                prompt = build_patch_prompt(kind, it, topk)
                d = call_llm_for_diff(prompt)
                if d and d.startswith("--- "):
                    diffs.append(d)

        handle("k8s", findings.get("k8s", []))
        handle("tf", findings.get("tf", []))
        handle("java", findings.get("java", []))
        handle("docker", findings.get("docker", []))

        if not diffs:
            print("No diffs generated.")
            return

        patch = OUTPUT / "agent_patch.diff"
        patch.write_text("\n\n".join(diffs), encoding="utf-8")

        branch = ensure_branch_and_apply_diff(patch)

        meta = OUTPUT / "agent_meta.json"
        meta.write_text(json.dumps({"branch": branch}), encoding="utf-8")

        print(f"Branch created: {branch}")

    except Exception as e:
        print(f"Agent failed safely: {e}")
        sys.exit(0)


if __name__ == "__main__":
    main()




# #!/usr/bin/env python3
# import os
# import sys
# import json
# import pathlib
# from typing import List, Set, Optional

# # ── Make 'tools/' the package root so 'agent' and 'embeddings' imports work ──
# HERE = pathlib.Path(__file__).resolve()
# TOOLS_ROOT = HERE.parents[1]  # .../tools
# REPO_ROOT = HERE.parents[2]   # repo root
# if str(TOOLS_ROOT) not in sys.path:
#     sys.path.insert(0, str(TOOLS_ROOT))

# from agent.utils.debug import log_topk
# from embeddings.retriever import RepoRetriever
# from agent.pick_findings import get_findings
# from agent.utils.prompt_lib import build_patch_prompt, call_llm_for_diff
# from agent.utils.git_ops import ensure_branch_and_apply_diff, open_pr

# # fixers
# from agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker

# OUTPUT = pathlib.Path(REPO_ROOT, "agent_output")
# OUTPUT.mkdir(parents=True, exist_ok=True)


# def _extract_diff_segments(text: str) -> List[str]:
#     """
#     Extract valid diff segments without altering file paths.
#     Accept:
#       - git-style blocks starting with 'diff --git ' (must contain at least one '@@')
#       - plain unified blocks starting with '--- <path>' then '+++ <path>' (must contain at least one '@@')
#     """
#     t = text.replace("\r\n", "\n").replace("\r", "\n")
#     lines = t.split("\n")

#     segs: List[str] = []
#     i = 0
#     n = len(lines)

#     def has_hunk(seg: str) -> bool:
#         return "@@" in seg

#     def flush(start: int, end: int):
#         seg = "\n".join(lines[start:end]).strip("\n")
#         if seg and ("--- " in seg) and ("+++ " in seg) and has_hunk(seg):
#             if not seg.endswith("\n"):
#                 seg += "\n"
#             segs.append(seg)

#     while i < n:
#         line = lines[i]

#         # git-style segment
#         if line.startswith("diff --git "):
#             s = i
#             i += 1
#             while i < n and not lines[i].startswith("diff --git "):
#                 i += 1
#             flush(s, i)
#             continue

#         # plain unified segment
#         if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
#             s = i
#             i += 2
#             while i < n and not (
#                 lines[i].startswith("--- ") or lines[i].startswith("diff --git ")
#             ):
#                 i += 1
#             flush(s, i)
#             continue

#         i += 1

#     return segs


# def _target_file_from_segment(segment: str) -> Optional[str]:
#     """
#     Extract the target file path from the first '+++ ' header.
#     Return a normalized path without leading a/ or b/.
#     """
#     for line in segment.split("\n"):
#         if line.startswith("+++ "):
#             p = line[4:].strip()
#             if "\t" in p:
#                 p = p.split("\t", 1)[0]
#             if p.startswith("a/") or p.startswith("b/"):
#                 p = p[2:]
#             return p
#     return None


# def _append_candidate(container: List[str], candidate: str, seen_paths: Set[str]):
#     segs = _extract_diff_segments(candidate)
#     if not segs:
#         return
#     for s in segs:
#         target = _target_file_from_segment(s)
#         # De-duplicate per target file to avoid conflicting hunks
#         if target and target in seen_paths:
#             continue
#         if s not in container:
#             container.append(s if s.endswith("\n") else s + "\n")
#             if target:
#                 seen_paths.add(target)


# def handle_findings(kind: str, items: list, retriever: RepoRetriever, diffs: list, seen_paths: Set[str]):
#     if not items:
#         return

#     fx_map = {
#         "k8s": fixer_k8s,
#         "tf": fixer_tf,
#         "java": fixer_java,
#         "docker": fixer_docker,
#     }
#     fx = fx_map[kind]

#     for it in items:
#         # 1) Deterministic
#         d = fx.try_deterministic(it)
#         if d:
#             log_topk(kind, it, query="(deterministic)", topk=[], mode="deterministic")
#             _append_candidate(diffs, d, seen_paths)
#             continue

#         # 2) RAG (repo-aware)
#         q = fx.query_for(it)
#         topk = retriever.search(q) if q else []
#         d = fx.try_rag_style(it, topk)
#         if d:
#             log_topk(kind, it, query=q, topk=topk, mode="rag")
#             _append_candidate(diffs, d, seen_paths)
#             continue

#         # 3) Trained-knowledge fallback (LLM prompt → diff)
#         log_topk(kind, it, query=q or "(no-query)", topk=topk, mode="trained")
#         prompt = build_patch_prompt(kind, it, topk)
#         d = call_llm_for_diff(prompt)
#         _append_candidate(diffs, d, seen_paths)


# def main():
#     min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
#     findings = get_findings(min_sev)
#     retriever = RepoRetriever(top_k=6)
#     diffs: List[str] = []
#     seen_paths: Set[str] = set()

#     handle_findings("k8s", findings.get("k8s", []), retriever, diffs, seen_paths)
#     handle_findings("tf", findings.get("tf", []), retriever, diffs, seen_paths)
#     handle_findings("java", findings.get("java", []), retriever, diffs, seen_paths)
#     handle_findings("docker", findings.get("docker", []), retriever, diffs, seen_paths)

#     if not diffs:
#         print("Agent generated no diffs; exiting.")
#         return

#     # Join with a blank line between segments
#     patch = OUTPUT / "agent_patch.diff"
#     patch.write_text("\n\n".join(diffs), encoding="utf-8")

#     # Apply the rewritten patch once and open a PR
#     br = ensure_branch_and_apply_diff(patch)
#     pr = open_pr(br, "Agentic AI autofix (deterministic→RAG→trained)", f"Threshold: {min_sev}\nAutomated minimal diffs.")
#     print(f"Branch: {br}\nPR: {pr}")


# if __name__ == "__main__":
#     main()