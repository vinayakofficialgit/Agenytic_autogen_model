#!/usr/bin/env python3
"""
Enterprise AI Security Intelligence Agent - V3 Hardened

Features:
- Batched LLM enrichment
- Robust JSON extraction
- ID-based mapping
- Deterministic fallback
- Dockerfile mapping for Trivy
- Line number support
- Expandable HTML dashboard
"""

import os
import json
import pathlib
import hashlib
import re
from datetime import datetime, UTC
from typing import List, Dict, Any
from openai import OpenAI

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

REPORTS_DIR = pathlib.Path("final-reports")
OUTPUT_DIR = pathlib.Path("agent_output")
OUTPUT_DIR.mkdir(exist_ok=True)

MIN_SEVERITY = os.getenv("MIN_SEVERITY", "HIGH").upper()
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"

SEV_ORDER = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def want(sev: str) -> bool:
    return SEV_ORDER.get(sev.upper(),0) >= SEV_ORDER.get(MIN_SEVERITY,3)

def load_json(p: pathlib.Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except:
        return {}

def fingerprint(v):
    return hashlib.sha256(
        f"{v['file']}|{v['rule']}|{v['severity']}".encode()
    ).hexdigest()

def extract_json(text):
    # Remove markdown fences
    text = re.sub(r"^```.*?\n", "", text, flags=re.S)
    text = text.replace("```", "").strip()

    # Extract JSON array safely
    match = re.search(r"\[.*\]", text, re.S)
    if match:
        return json.loads(match.group(0))

    return json.loads(text)


# ------------------------------------------------------------
# Parse Reports
# ------------------------------------------------------------

def parse_reports():

    findings = []

    for file in REPORTS_DIR.glob("*.json"):
        data = load_json(file)

        # -------- SEMGREP --------
        if file.name == "semgrep.json":
            for r in data.get("results", []):
                extra = r.get("extra", {})
                sev = (extra.get("severity") or "LOW").upper()
                if sev == "ERROR": sev="HIGH"
                if not want(sev): continue

                findings.append({
                    "tool": "semgrep",
                    "severity": sev,
                    "rule": extra.get("rule_id"),
                    "file": r.get("path"),
                    "line": (r.get("start") or {}).get("line"),
                    "description": extra.get("message"),
                })

        # -------- TRIVY IMAGE --------
        elif file.name == "trivy_image.json":
            for res in data.get("Results", []):
                for v in res.get("Vulnerabilities",[]) or []:
                    sev = (v.get("Severity") or "LOW").upper()
                    if not want(sev): continue

                    findings.append({
                        "tool": "trivy_image",
                        "severity": sev,
                        "rule": v.get("VulnerabilityID"),
                        "file": "java-pilot-app/Dockerfile",
                        "line": None,
                        "description": f"{v.get('PkgName')} {v.get('InstalledVersion')}",
                    })

        # -------- CHECKOV --------
        elif file.name in ["checkov_tf.json","checkov_k8s.json"]:
            tool_name=file.name.replace(".json","")
            for f in data.get("results",{}).get("failed_checks",[]) or []:
                sev=(f.get("severity") or "LOW").upper()
                if not want(sev): continue

                findings.append({
                    "tool": tool_name,
                    "severity": sev,
                    "rule": f.get("check_id"),
                    "file": f.get("file_path"),
                    "line": (f.get("file_line_range") or [None])[0],
                    "description": f.get("check_name"),
                })

    # Deduplicate
    unique={}
    for f in findings:
        fp=fingerprint(f)
        if fp not in unique:
            unique[fp]=f

    # Assign IDs
    results=list(unique.values())
    for i,f in enumerate(results):
        f["id"]=i

    return results


#-------------------------------------------------------------
# Executive Summary
#-------------------------------------------------------------

def print_executive_summary(all_findings: List[Dict[str, Any]]):

    from collections import Counter

    total = len(all_findings)
    sev_counter = Counter([f["severity"].upper() for f in all_findings])

    critical = sev_counter.get("CRITICAL", 0)
    high = sev_counter.get("HIGH", 0)
    medium = sev_counter.get("MEDIUM", 0)
    low = sev_counter.get("LOW", 0)

    risk_level = "LOW"
    if critical > 0:
        risk_level = "CRITICAL"
    elif high > 5:
        risk_level = "HIGH"
    elif high > 0:
        risk_level = "ELEVATED"

    print("\n" + "=" * 120)
    print("EXECUTIVE SECURITY SUMMARY")
    print("=" * 120)
    print(f"Total Vulnerabilities Detected : {total}")
    print(f"Critical : {critical}")
    print(f"High     : {high}")
    print(f"Medium   : {medium}")
    print(f"Low      : {low}")
    print("-" * 120)
    print(f"Overall Risk Posture : {risk_level}")
    print("=" * 120 + "\n")

# ------------------------------------------------------------
# Aggregate Table Implementation
#-------------------------------------------------------------
# def print_aggregate_summary(findings: List[Dict[str, Any]]):

#     if not findings:
#         print("No findings to summarize.")
#         return

#     from collections import defaultdict

#     tool_stats = {}
#     tool_cve_map = defaultdict(list)

#     for f in findings:
#         tool = f.get("tool", "unknown")
#         sev = f.get("severity", "LOW").upper()
#         rule = f.get("rule", "")
#         file = f.get("file", "")

#         if tool not in tool_stats:
#             tool_stats[tool] = {
#                 "total": 0,
#                 "CRITICAL": 0,
#                 "HIGH": 0,
#                 "MEDIUM": 0,
#                 "LOW": 0,
#             }

#         tool_stats[tool]["total"] += 1
#         if sev in tool_stats[tool]:
#             tool_stats[tool][sev] += 1

#         if rule:
#             tool_cve_map[tool].append(f"{rule} : {file}")

#     print("\n" + "=" * 120)
#     print("AGGREGATED SCAN SUMMARY (MIN_SEVERITY = {})".format(MIN_SEVERITY))
#     print("=" * 120)

#     header = (
#         f"{'Tool':15} | "
#         f"{'Total':5} | "
#         f"{'Critical':8} | "
#         f"{'High':5} | "
#         f"{'Medium':7} | "
#         f"{'Low':4} | "
#         f"{'CVE IDs':30} | "
#         f"{'CVE -> File'}"
#     )
#     print(header)
#     print("-" * len(header))

#     for tool, stats in tool_stats.items():

#         cves = list(set([x.split(" : ")[0] for x in tool_cve_map[tool]]))
#         cve_files = tool_cve_map[tool]

#         print(
#             f"{tool:15} | "
#             f"{stats['total']:5} | "
#             f"{stats['CRITICAL']:8} | "
#             f"{stats['HIGH']:5} | "
#             f"{stats['MEDIUM']:7} | "
#             f"{stats['LOW']:4} | "
#             f"{', '.join(cves)[:30]:30} | "
#             f"{', '.join(cve_files)[:60]}"
#         )

#     print("=" * 120 + "\n")

def print_threshold_summary(findings: List[Dict[str, Any]]):

    from collections import defaultdict

    tool_stats = {}
    tool_cve_map = defaultdict(list)

    for f in findings:
        tool = f["tool"]
        sev = f["severity"].upper()
        rule = f.get("rule", "")
        file = f.get("file", "")

        if tool not in tool_stats:
            tool_stats[tool] = {
                "total": 0,
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }

        tool_stats[tool]["total"] += 1
        tool_stats[tool][sev] += 1

        if rule:
            tool_cve_map[tool].append(f"{rule} : {file}")

    print("\n" + "=" * 120)
    print(f"AGGREGATED SCAN SUMMARY (MIN_SEVERITY = {MIN_SEVERITY})")
    print("=" * 120)

    header = (
        f"{'Tool':15} | "
        f"{'Total':5} | "
        f"{'Critical':8} | "
        f"{'High':5} | "
        f"{'Medium':7} | "
        f"{'Low':4} | "
        f"{'CVE IDs':30} | "
        f"{'CVE -> File'}"
    )
    print(header)
    print("-" * len(header))

    for tool, stats in tool_stats.items():
        cves = list(set([x.split(" : ")[0] for x in tool_cve_map[tool]]))
        cve_files = tool_cve_map[tool]

        print(
            f"{tool:15} | "
            f"{stats['total']:5} | "
            f"{stats['CRITICAL']:8} | "
            f"{stats['HIGH']:5} | "
            f"{stats['MEDIUM']:7} | "
            f"{stats['LOW']:4} | "
            f"{', '.join(cves)[:30]:30} | "
            f"{', '.join(cve_files)[:60]}"
        )

    print("=" * 120 + "\n")


#------------------------------------------------------------
# Full Inventory
#------------------------------------------------------------

def print_full_inventory(all_findings: List[Dict[str, Any]]):

    print("\n" + "=" * 120)
    print("FULL VULNERABILITY INVENTORY (ALL SEVERITIES)")
    print("=" * 120)

    header = (
        f"{'Severity':10} | "
        f"{'Tool':15} | "
        f"{'Rule/CVE':20} | "
        f"{'File':40} | "
        f"{'Line'}"
    )
    print(header)
    print("-" * len(header))

    for f in all_findings:
        print(
            f"{f['severity']:10} | "
            f"{f['tool']:15} | "
            f"{(f.get('rule') or '')[:20]:20} | "
            f"{(f.get('file') or '')[:40]:40} | "
            f"{f.get('line')}"
        )

    print("=" * 120 + "\n")

# ------------------------------------------------------------
# Deterministic Fallback
# ------------------------------------------------------------

def deterministic_analysis(v):
    return {
        "technical_explanation": f"{v['rule']} detected by {v['tool']}.",
        "business_impact": "Potential exploitation risk.",
        "remediation_steps": "Upgrade affected component or apply secure coding practices.",
        "risk_score": 7 if v["severity"] in ["CRITICAL","HIGH"] else 5
    }


# ------------------------------------------------------------
# Batched LLM Enrichment
# ------------------------------------------------------------

def batch_enrich(findings):

    if not LLM_ENABLED or not findings:
        for f in findings:
            f["ai_analysis"]=deterministic_analysis(f)
        return findings

    client=OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt=f"""
You are a senior enterprise security architect.

For each vulnerability in the JSON array below,
return enriched analysis in JSON array format with SAME IDs.

Required keys:
id
technical_explanation
business_impact
remediation_steps
risk_score (1-10)

Vulnerabilities:
{json.dumps(findings,indent=2)}
"""

    try:
        response=client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role":"user","content":prompt}],
            temperature=0.2,
        )

        enriched=extract_json(response.choices[0].message.content.strip())

        enriched_map={e["id"]:e for e in enriched if "id" in e}

        for f in findings:
            f["ai_analysis"]=enriched_map.get(f["id"],deterministic_analysis(f))

    except Exception as e:
        print("⚠ LLM enrichment failed:",e)
        for f in findings:
            f["ai_analysis"]=deterministic_analysis(f)

    return findings


# ------------------------------------------------------------
# HTML Generator
# ------------------------------------------------------------

def generate_html(findings):

    rows=""
    for f in findings:
        ai=f.get("ai_analysis",{})
        rows+=f"""
<tr>
<td>{f['severity']}</td>
<td>{f['tool']}</td>
<td>{f['rule']}</td>
<td>{f['file']}</td>
<td>{f.get('line','')}</td>
<td>{ai.get('risk_score','')}</td>
<td>
<details>
<summary>View Analysis</summary>
<b>Technical:</b> {ai.get('technical_explanation','')}<br>
<b>Business Impact:</b> {ai.get('business_impact','')}<br>
<b>Remediation:</b> {ai.get('remediation_steps','')}
</details>
</td>
</tr>
"""

    return f"""
<html>
<head>
<title>AI Security Intelligence</title>
<style>
body{{font-family:Arial;background:#0f172a;color:#e2e8f0}}
table{{width:100%;border-collapse:collapse}}
td,th{{border:1px solid #334155;padding:8px}}
th{{background:#1e293b}}
</style>
</head>
<body>
<h1>AI Security Intelligence Dashboard (V3)</h1>
<p>Generated: {datetime.now(UTC).isoformat()}</p>
<p>Threshold: {MIN_SEVERITY}</p>
<table>
<tr>
<th>Severity</th>
<th>Tool</th>
<th>CVE/Rule</th>
<th>File</th>
<th>Line</th>
<th>Risk</th>
<th>Details</th>
</tr>
{rows}
</table>
</body>
</html>
"""


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    print("Collecting findings...")
    # findings=parse_reports()

    all_findings = parse_reports()

    print_executive_summary(all_findings)
    print_full_inventory(all_findings)
    
    # Filter by MIN_SEVERITY for intelligence enrichment
    filtered_findings = [f for f in all_findings if want(f["severity"])]
    
    print_threshold_summary(filtered_findings)

    # print_aggregate_summary(findings)
    print(f"{len(findings)} vulnerabilities above threshold.")

    findings=batch_enrich(findings)

    (OUTPUT_DIR/"ai_security_intelligence.json").write_text(
        json.dumps(findings,indent=2)
    )

    (OUTPUT_DIR/"ai_security_dashboard.html").write_text(
        generate_html(findings)
    )

    print("AI Security Intelligence V3 generated successfully.")


if __name__=="__main__":
    main()

#######WORKING CODE BUT TO AVOID API CALLS FOR EACH VULN AND SEND IN BATCH ALL VULN WITH 1 API CALL ABOVE CODE DONE########
# #!/usr/bin/env python3
# """
# Enterprise AI Security Intelligence Agent
# ------------------------------------------

# LLM-powered vulnerability enrichment engine.

# Outputs:
#  - agent_output/ai_security_intelligence.json
#  - agent_output/ai_security_dashboard.html
#  - agent_output/executive_security_summary.md

# Safe for CI/CD usage.
# """

# import os
# import json
# import pathlib
# import hashlib
# from datetime import datetime, UTC
# from typing import List, Dict, Any

# from openai import OpenAI


# # ============================================================
# # Configuration
# # ============================================================

# REPORTS_DIR = pathlib.Path("final-reports")
# OUTPUT_DIR = pathlib.Path("agent_output")
# OUTPUT_DIR.mkdir(exist_ok=True)

# MIN_SEVERITY = os.getenv("MIN_SEVERITY", "HIGH").upper()
# LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"

# SEV_ORDER = {
#     "CRITICAL": 4,
#     "HIGH": 3,
#     "MEDIUM": 2,
#     "LOW": 1
# }


# # ============================================================
# # Utility Functions
# # ============================================================

# def want(sev: str) -> bool:
#     return SEV_ORDER.get(sev.upper(), 0) >= SEV_ORDER.get(MIN_SEVERITY, 3)


# def load_json(path: pathlib.Path):
#     try:
#         return json.loads(path.read_text(encoding="utf-8"))
#     except Exception:
#         return {}


# def fingerprint(v: Dict[str, Any]) -> str:
#     key = f"{v['file']}|{v['rule']}|{v['severity']}"
#     return hashlib.sha256(key.encode()).hexdigest()


# # ============================================================
# # Parsing Scanners
# # ============================================================

# def parse_reports() -> List[Dict]:

#     findings = []

#     for file in REPORTS_DIR.glob("*.json"):
#         data = load_json(file)

#         # ---------------- SEMGREP ----------------
#         if file.name == "semgrep.json":
#             for r in data.get("results", []):
#                 extra = r.get("extra", {})
#                 sev = (extra.get("severity") or "LOW").upper()

#                 if sev == "ERROR":
#                     sev = "HIGH"
#                 elif sev == "WARNING":
#                     sev = "MEDIUM"

#                 if not want(sev):
#                     continue

#                 findings.append({
#                     "tool": "semgrep",
#                     "severity": sev,
#                     "rule": extra.get("rule_id") or "",
#                     "file": r.get("path"),
#                     "description": extra.get("message"),
#                 })

#         # ---------------- TRIVY IMAGE ----------------
#         elif file.name == "trivy_image.json":
#             for res in data.get("Results", []):
#                 target = res.get("Target")
#                 for v in res.get("Vulnerabilities", []) or []:
#                     sev = (v.get("Severity") or "LOW").upper()
#                     if not want(sev):
#                         continue

#                     findings.append({
#                         "tool": "trivy_image",
#                         "severity": sev,
#                         "rule": v.get("VulnerabilityID"),
#                         "file": target,
#                         "description": f"{v.get('PkgName')} {v.get('InstalledVersion')}",
#                     })

#         # ---------------- CHECKOV ----------------
#         elif file.name in ["checkov_tf.json", "checkov_k8s.json"]:
#             tool_name = file.name.replace(".json", "")
#             for f in data.get("results", {}).get("failed_checks", []) or []:
#                 sev = (f.get("severity") or "LOW").upper()
#                 if not want(sev):
#                     continue

#                 findings.append({
#                     "tool": tool_name,
#                     "severity": sev,
#                     "rule": f.get("check_id"),
#                     "file": f.get("file_path"),
#                     "description": f.get("check_name"),
#                 })

#     # Deduplicate
#     unique = {}
#     for f in findings:
#         fp = fingerprint(f)
#         if fp not in unique:
#             unique[fp] = f

#     return list(unique.values())


# # ============================================================
# # LLM Enrichment
# # ============================================================

# def enrich_with_llm(vuln: Dict[str, Any]) -> Dict[str, Any]:

#     if not LLM_ENABLED:
#         vuln["ai_analysis"] = "LLM disabled."
#         return vuln

#     client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

#     prompt = f"""
# You are a senior security architect.

# Analyze the vulnerability below and respond strictly in JSON format.

# Vulnerability Details:
# Tool: {vuln['tool']}
# Severity: {vuln['severity']}
# Rule/CVE: {vuln['rule']}
# File: {vuln['file']}
# Description: {vuln['description']}

# Return JSON with keys:
# technical_explanation
# exploitation_scenario
# business_impact
# remediation_steps
# upgrade_guidance
# risk_score (1-10)
# """

#     try:
#         response = client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.2,
#         )

#         content = response.choices[0].message.content.strip()

#         # Attempt JSON parse
#         ai_json = json.loads(content)
#         vuln["ai_analysis"] = ai_json

#     except Exception as e:
#         vuln["ai_analysis"] = {
#             "error": str(e),
#             "technical_explanation": "LLM analysis failed."
#         }

#     return vuln


# # ============================================================
# # HTML Generator
# # ============================================================

# def generate_html(findings: List[Dict]):

#     rows = ""

#     for f in findings:
#         ai = f.get("ai_analysis", {})
#         risk = ai.get("risk_score", "N/A")

#         rows += f"""
#         <tr>
#             <td>{f['severity']}</td>
#             <td>{f['tool']}</td>
#             <td>{f['rule']}</td>
#             <td>{f['file']}</td>
#             <td>{risk}</td>
#             <td>{ai.get('technical_explanation','')}</td>
#         </tr>
#         """

#     html = f"""
# <!DOCTYPE html>
# <html>
# <head>
# <title>AI Security Intelligence Dashboard</title>
# <style>
# body {{ font-family: Arial; background:#0f172a; color:#e2e8f0; }}
# table {{ width:100%; border-collapse: collapse; }}
# th, td {{ padding:8px; border:1px solid #334155; }}
# th {{ background:#1e293b; }}
# </style>
# </head>
# <body>

# <h1>AI-Powered Security Intelligence Report</h1>
# <p>Generated: {datetime.now(UTC).isoformat()}</p>
# <p>Threshold: {MIN_SEVERITY}</p>

# <table>
# <tr>
# <th>Severity</th>
# <th>Tool</th>
# <th>Rule/CVE</th>
# <th>File</th>
# <th>Risk Score</th>
# <th>Technical Summary</th>
# </tr>
# {rows}
# </table>

# </body>
# </html>
# """

#     return html


# # ============================================================
# # Main
# # ============================================================

# def main():

#     print("🔎 Collecting vulnerabilities...")
#     findings = parse_reports()

#     print(f"Found {len(findings)} vulnerabilities ≥ {MIN_SEVERITY}")

#     enriched = []

#     for idx, vuln in enumerate(findings, 1):
#         print(f"Enriching {idx}/{len(findings)}: {vuln['rule']}")
#         enriched.append(enrich_with_llm(vuln))

#     # Write JSON
#     json_out = OUTPUT_DIR / "ai_security_intelligence.json"
#     json_out.write_text(json.dumps(enriched, indent=2))

#     # Write HTML
#     html_out = OUTPUT_DIR / "ai_security_dashboard.html"
#     html_out.write_text(generate_html(enriched), encoding="utf-8")

#     # Executive Summary
#     exec_md = OUTPUT_DIR / "executive_security_summary.md"
#     exec_md.write_text(f"""
# # Executive Security Summary

# Generated: {datetime.now(UTC).isoformat()}
# Threshold: {MIN_SEVERITY}
# Total Findings: {len(enriched)}

# ## Severity Breakdown

# CRITICAL: {sum(1 for f in enriched if f['severity']=="CRITICAL")}
# HIGH: {sum(1 for f in enriched if f['severity']=="HIGH")}
# MEDIUM: {sum(1 for f in enriched if f['severity']=="MEDIUM")}
# LOW: {sum(1 for f in enriched if f['severity']=="LOW")}
# """)

#     print("✅ AI Security Intelligence Report Generated.")
#     print(f"HTML: {html_out}")
#     print(f"JSON: {json_out}")


# if __name__ == "__main__":
#     main()