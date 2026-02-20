# agents/advisor.py
"""
AI Remediation Advisor

Provides:
✅ root cause explanation
✅ exploitability
✅ business impact
✅ step-by-step remediation
✅ config fix
✅ code fix guidance
✅ verification steps
✅ prevention guidance
"""

import os
import json
from pathlib import Path
from openai import OpenAI


class AdvisorAgent:

    def __init__(self, output_dir: Path):
        self.out = Path(output_dir)
        self.client = OpenAI()

    def _build_prompt(self, finding):

        return f"""
You are a senior DevSecOps security architect.

Provide structured remediation intelligence.

Return STRICT JSON with keys:
- root_cause
- exploitability
- business_impact
- remediation_steps
- config_fix
- code_fix
- verification_steps
- prevention_guidance
- patch_diff_if_possible

Finding:
{json.dumps(finding)[:4000]}
"""

    def generate(self, grouped):

        enriched = {}

        for tool, findings in grouped.items():

            enriched[tool] = []

            for f in findings[:20]:  # avoid token explosion

                try:
                    prompt = self._build_prompt(f)

                    resp = self.client.chat.completions.create(
                        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.2,
                    )

                    data = resp.choices[0].message.content

                    try:
                        ai = json.loads(data)
                        f.update({"ai_remediation": ai})
                    except:
                        f["ai_remediation"] = {"raw": data}

                except Exception as e:
                    f["ai_remediation"] = {"error": str(e)}

                enriched[tool].append(f)

        self.out.mkdir(exist_ok=True)

        (self.out / "ai_remediation.json").write_text(
            json.dumps(enriched, indent=2)
        )

        # ⭐ also human readable md
        md = []
        for tool, items in enriched.items():
            md.append(f"## {tool}\n")
            for it in items:
                md.append(f"- {it.get('title')}\n")
                md.append(json.dumps(it.get("ai_remediation"), indent=2))
                md.append("\n")

        (self.out / "ai_remediation.md").write_text("\n".join(md))

        return enriched


# #advisor.py
# ADVISOR_SYSTEM = """You are a senior secure-coding reviewer.
# Given scanner findings and code snippets, you will:
# 1) Prioritize by severity and exploitability.
# 2) Explain root cause and the minimal safe fix.
# 3) Propose unified diffs (git patch format) per file when possible.
# 4) Keep changes minimal and compatible with Python {python_version}.
# 5) Avoid speculative edits—if unsure, say so.

# Return exactly TWO parts in this order:
# [PART 1: MARKDOWN]
# A concise, human-readable plan with bullets and small code blocks.

# [PART 2: JSON]
# A single JSON object with this schema:
# {{
#   "schema": "advisor.v1",
#   "suggestions": [
#     {{
#       "id": "string",
#       "title": "string",
#       "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
#       "targets": [{{"file":"path","start_line":int|null,"end_line":int|null}}],
#       "rationale": "string",
#       "fix": {{
#         "summary": "string",
#         "diff": "string|null"  // unified diff or null
#       }}
#     }}
#   ]
# }}
# """
