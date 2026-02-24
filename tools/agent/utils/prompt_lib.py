import os
from typing import List, Dict, Any
from openai import OpenAI

def build_patch_prompt(kind: str, finding: dict, context: List[Dict[str,Any]]) -> str:
    ctx_txt = []
    for c in context or []:
        m = c["meta"]; path = m.get("path",""); ch = m.get("chunk",0)
        ctx_txt.append(f"[{path}#chunk{ch}] score={c.get('score',0):.3f}\n{c.get('snippet','')}")
    ctx = "\n\n".join(ctx_txt)

    return f"""You are a senior platform security engineer.
You MUST output a valid unified git diff ONLY (no prose), with correct file paths.

Finding:
- Type: {kind}
- File: {finding.get('file')}
- Line: {finding.get('line')}
- Rule: {finding.get('rule')}
- Detail: {finding.get('detail')}

Repository context (Top-K):
{ctx}

Rules:
- Make the smallest safe change to fix the issue.
- Preserve formatting and project conventions shown in context.
- Do not refactor unrelated code.
- Output only a unified diff."""
    
def call_llm_for_diff(prompt: str) -> str:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY",""))
    # Use a capable model available to you
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"system","content":"Return only unified diff."},
                  {"role":"user","content":prompt}],
        temperature=0.1,
        max_tokens=1200,
    )
    return resp.choices[0].message.content.strip()