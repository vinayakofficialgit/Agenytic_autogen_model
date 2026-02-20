import os
import json
import argparse
from pathlib import Path
from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def load_grouped_findings(output_dir: Path):
    p = output_dir / "findings_grouped.json"
    if not p.exists():
        raise FileNotFoundError("findings_grouped.json missing")
    return json.loads(p.read_text())


def build_prompt(grouped):
    return f"""
You are a principal DevSecOps security triage AI.

For EACH finding produce enrichment:

FIELDS:
- exploitability: low/medium/high
- reachability: internal/public
- business_impact: low/medium/high
- noise: true/false
- chain: true/false (part of exploit chain)
- confidence: 0-1
- autofix_possible: true/false
- remediation
- risk_score: integer 1-20

Also produce:
- exploit_chains: list of correlated finding ids
- risk_summary
- decision_hint PASS/FAIL

Return STRICT JSON:
{{
 "enriched_findings": [],
 "exploit_chains": [],
 "risk_summary": {{}},
 "decision_hint": "PASS/FAIL"
}}

Findings:
{json.dumps(grouped)[:12000]}
"""

def normalize_ai_output(data):
    enriched = data.get("enriched_findings", [])

    for f in enriched:
        f.setdefault("exploitability", "low")
        f.setdefault("reachability", "internal")
        f.setdefault("business_impact", "low")
        f.setdefault("noise", False)
        f.setdefault("chain", False)
        f.setdefault("confidence", 0.5)
        f.setdefault("risk_score", 5)

    return data

def run_ai(grouped):
    client = OpenAI()
    prompt = build_prompt(grouped)

    res = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )

    return res.choices[0].message.content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    grouped = load_grouped_findings(output_dir)

    ai_output = run_ai(grouped)

    try:
        structured = normalize_ai_output(json.loads(ai_output))
    except Exception:
        structured = {"raw": ai_output}

    (output_dir / "ai_enriched_findings.json").write_text(
        json.dumps(structured, indent=2)
    )

    (output_dir / "ai_summary.md").write_text(ai_output)


if __name__ == "__main__":
    main()


# import os
# import json
# import argparse
# from pathlib import Path
# from openai import OpenAI

# MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


# def load_reports(reports_dir: Path):
#     findings = []
#     for file in reports_dir.glob("*.json"):
#         try:
#             data = json.loads(file.read_text())
#             findings.append({"file": file.name, "content": data})
#         except Exception:
#             continue
#     return findings


# def build_prompt(findings):
#     return f"""
# You are a senior DevSecOps security analyst.

# Analyze aggregated scan findings across tools.

# Perform:
# 1. Risk prioritization
# 2. Noise reduction
# 3. Exploit chain detection
# 4. Business impact estimation
# 5. Remediation hints

# Return STRICT JSON with keys:
# - summary
# - critical_findings
# - priority_map
# - remediation_hints

# Findings:
# {json.dumps(findings)[:12000]}
# """


# def run_ai(findings):
#     client = OpenAI()
#     prompt = build_prompt(findings)

#     response = client.chat.completions.create(
#         model=MODEL,
#         messages=[{"role": "user", "content": prompt}],
#         temperature=0.2,
#     )

#     content = response.choices[0].message.content
#     return content


# def main():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--reports-dir", required=True)
#     parser.add_argument("--output-dir", required=True)
#     args = parser.parse_args()

#     reports_dir = Path(args.reports_dir)
#     output_dir = Path(args.output_dir)
#     output_dir.mkdir(exist_ok=True)

#     findings = load_reports(reports_dir)

#     ai_output = run_ai(findings)

#     try:
#         structured = json.loads(ai_output)
#     except Exception:
#         structured = {"raw": ai_output}

#     (output_dir / "ai_security_review.json").write_text(
#         json.dumps(structured, indent=2)
#     )

#     (output_dir / "ai_security_review.md").write_text(ai_output)


# if __name__ == "__main__":
#     main()