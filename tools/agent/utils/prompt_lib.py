#!/usr/bin/env python3
import os
from typing import List, Dict, Any
from openai import OpenAI

# Model names pulled from env or default to recommended value
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
APP_DIR = os.getenv("APP_DIR", "java-pilot-app")

def build_patch_prompt(kind: str, finding: dict, context: List[Dict[str, Any]]) -> str:
    """
    Build a strict unified-diff-only prompt for the LLM.
    """
    ctx_txt = []
    for c in context or []:
        meta = c.get("meta", {})
        path = meta.get("path", "")
        chunk = meta.get("chunk", 0)
        score = c.get("score", 0)
        snippet = c.get("snippet", "")

        ctx_txt.append(
            f"[{path}#chunk{chunk}] score={score:.3f}\n{snippet}"
        )

    joined_context = "\n\n".join(ctx_txt)

    return f"""
You are a senior platform security engineer.
You MUST output a valid unified git diff ONLY (no explanations).
Paths MUST be repo-relative and include the '{APP_DIR}/' module prefix when applicable.

Finding Details:
- Type: {kind}
- File: {finding.get('file')}
- Line: {finding.get('line')}
- Rule: {finding.get('rule')}
- Detail: {finding.get('detail')}

Repository Top-K Context:
{joined_context}

Rules:
- Smallest safe change ONLY.
- Preserve code style.
- NO comments, NO narrative.
- Output must start with '--- ' and contain only unified diff format.
"""

def call_llm_for_diff(prompt: str) -> str:
    """
    Calls the LLM and returns ONLY the diff text.
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": "Return ONLY a unified git diff. No prose."},
            {"role": "user",   "content": prompt}
        ],
        temperature=0.1,
        max_tokens=1500
    )

    diff = response.choices[0].message.content.strip()

    # Safety: ensure diff starts with expected prefix
    if diff.startswith("--- "):
        return diff
    else:
        # LLM sometimes returns lines before diff — strip until first diff block
        for line in diff.splitlines():
            if line.startswith("--- "):
                idx = diff.index(line)
                return diff[idx:]
        return diff  # fallback (may still break git apply)


# import os
# from typing import List, Dict, Any
# from openai import OpenAI

# APP_DIR = os.getenv("APP_DIR", "java-pilot-app")

# def build_patch_prompt(kind: str, finding: dict, context: List[Dict[str,Any]]) -> str:
#     ctx_txt = []
#     for c in context or []:
#         m = c["meta"]; path = m.get("path",""); ch = m.get("chunk",0)
#         ctx_txt.append(f"[{path}#chunk{ch}] score={c.get('score',0):.3f}\n{c.get('snippet','')}")
#     ctx = "\n\n".join(ctx_txt)

#     return f"""You are a senior platform security engineer.
# You MUST output a valid unified git diff ONLY (no prose), with file paths relative to the repository root.
# If the file is inside the '{APP_DIR}/' module, include that prefix in the path.

# Finding:
# - Type: {kind}
# - File: {finding.get('file')}
# - Line: {finding.get('line')}
# - Rule: {finding.get('rule')}
# - Detail: {finding.get('detail')}

# Repository context (Top-K):
# {ctx}

# Rules:
# - Make the smallest safe change to fix the issue.
# - Preserve formatting and project conventions shown in context.
# - Do not refactor unrelated code.
# - Output only a unified diff.
# """


# # import os
# # from typing import List, Dict, Any
# # from openai import OpenAI

# # def build_patch_prompt(kind: str, finding: dict, context: List[Dict[str,Any]]) -> str:
# #     ctx_txt = []
# #     for c in context or []:
# #         m = c["meta"]; path = m.get("path",""); ch = m.get("chunk",0)
# #         ctx_txt.append(f"[{path}#chunk{ch}] score={c.get('score',0):.3f}\n{c.get('snippet','')}")
# #     ctx = "\n\n".join(ctx_txt)

# #     return f"""You are a senior platform security engineer.
# # You MUST output a valid unified git diff ONLY (no prose), with correct file paths.

# # Finding:
# # - Type: {kind}
# # - File: {finding.get('file')}
# # - Line: {finding.get('line')}
# # - Rule: {finding.get('rule')}
# # - Detail: {finding.get('detail')}

# # Repository context (Top-K):
# # {ctx}

# # Rules:
# # - Make the smallest safe change to fix the issue.
# # - Preserve formatting and project conventions shown in context.
# # - Do not refactor unrelated code.
# # - Output only a unified diff."""
    
# # def call_llm_for_diff(prompt: str) -> str:
# #     client = OpenAI(api_key=os.getenv("OPENAI_API_KEY",""))
# #     # Use a capable model available to you
# #     model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
# #     resp = client.chat.completions.create(
# #         model=model,
# #         messages=[{"role":"system","content":"Return only unified diff."},
# #                   {"role":"user","content":prompt}],
# #         temperature=0.1,
# #         max_tokens=1200,
# #     )
# #     return resp.choices[0].message.content.strip()