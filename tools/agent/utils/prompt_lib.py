from openai import OpenAI
import os


def call_llm_rewrite(kind: str, finding: dict, original_content: str) -> str:
    """
    Enterprise-safe LLM rewrite.
    Returns FULL corrected file content.
    Never returns diff.
    """

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""
You are a senior DevSecOps security engineer.

Fix the security vulnerability in this file.

STRICT RULES:
- Return the FULL corrected file.
- Do NOT return a diff.
- Do NOT remove unrelated code.
- Do NOT delete the file.
- Only fix the vulnerability.

Finding:
Tool: {finding.get("tool")}
Rule: {finding.get("rule")}
Detail: {finding.get("detail")}
Severity: {finding.get("severity")}

Original File:
---------------------
{original_content}
---------------------
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
    )

    return response.choices[0].message.content.strip()