# advisor.py
"""
Advisor Agent
-------------
Generates AI remediation intelligence.
"""

import os
import json
from pathlib import Path
from typing import Dict
from openai import OpenAI


class AdvisorAgent:

    def __init__(self, output_dir: Path):
        """Initialize advisor with output directory."""
        self.out = Path(output_dir)
        self.client = OpenAI() if os.getenv("OPENAI_API_KEY") else None

    # -------------------------
    def _safe_json(self, txt):
        """Safely parse JSON from LLM output."""
        try:
            return json.loads(txt)
        except Exception:
            try:
                txt = txt.split("```json")[-1].split("```")[0]
                return json.loads(txt)
            except Exception:
                return {"raw": txt}

    # -------------------------
    def _build_prompt(self, finding):
        """Construct remediation intelligence prompt."""
        return f"""
Provide remediation intelligence as JSON.

Finding:
{json.dumps(finding)[:4000]}
"""

    # -------------------------
    def generate(self, grouped: Dict):
        """Generate remediation suggestions for findings."""
        enriched = {}

        for tool, findings in grouped.items():
            enriched[tool] = []

            for f in findings[:20]:
                f_copy = dict(f)

                if not self.client:
                    f_copy["ai_remediation"] = {"error": "no api key"}
                    enriched[tool].append(f_copy)
                    continue

                try:
                    resp = self.client.chat.completions.create(
                        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                        messages=[{"role": "user", "content": self._build_prompt(f)}],
                        temperature=0.2,
                    )

                    ai = self._safe_json(resp.choices[0].message.content)
                    f_copy["ai_remediation"] = ai

                except Exception as e:
                    f_copy["ai_remediation"] = {"error": str(e)}

                enriched[tool].append(f_copy)

        self.out.mkdir(exist_ok=True)

        (self.out / "ai_remediation.json").write_text(json.dumps(enriched, indent=2))

        md = []
        for tool, items in enriched.items():
            md.append(f"## {tool}")
            for it in items:
                md.append(f"- {it.get('title')}")
                md.append(json.dumps(it.get("ai_remediation"), indent=2))

        (self.out / "ai_remediation.md").write_text("\n".join(md))

        return enriched