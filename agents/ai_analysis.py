import os
import json
import argparse
from pathlib import Path
from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def load_reports(reports_dir: Path):
    findings = []
    for file in reports_dir.glob("*.json"):
        try:
            data = json.loads(file.read_text())
            findings.append({"file": file.name, "content": data})
        except Exception:
            continue
    return findings


def build_prompt(findings):
    return f"""
You are a senior DevSecOps security analyst.

Analyze aggregated scan findings across tools.

Perform:
1. Risk prioritization
2. Noise reduction
3. Exploit chain detection
4. Business impact estimation
5. Remediation hints

Return STRICT JSON with keys:
- summary
- critical_findings
- priority_map
- remediation_hints

Findings:
{json.dumps(findings)[:12000]}
"""


def run_ai(findings):
    client = OpenAI()
    prompt = build_prompt(findings)

    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )

    content = response.choices[0].message.content
    return content


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)

    findings = load_reports(reports_dir)

    ai_output = run_ai(findings)

    try:
        structured = json.loads(ai_output)
    except Exception:
        structured = {"raw": ai_output}

    (output_dir / "ai_security_review.json").write_text(
        json.dumps(structured, indent=2)
    )

    (output_dir / "ai_security_review.md").write_text(ai_output)


if __name__ == "__main__":
    main()