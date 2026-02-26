#!/usr/bin/env python3
"""
Enterprise AI Security Intelligence Agent - V4 Hardened

Features:
- Centralized severity policy
- Threshold + Exact mode
- Executive summary
- Full inventory
- Aggregated threshold table
- Batched LLM enrichment
- Deterministic fallback
- HTML dashboard
"""

import os
import json
import pathlib
import hashlib
import re
from datetime import datetime, UTC
from typing import List, Dict, Any
from collections import Counter, defaultdict
from openai import OpenAI

from tools.agent.utils.severity_policy import want, MIN_SEVERITY, SEVERITY_MODE

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

REPORTS_DIR = pathlib.Path("final-reports")
OUTPUT_DIR = pathlib.Path("agent_output")
OUTPUT_DIR.mkdir(exist_ok=True)

LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"

# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

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
    text = re.sub(r"^```.*?\n", "", text, flags=re.S)
    text = text.replace("```", "").strip()
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
                if sev == "ERROR": sev = "HIGH"
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
                for v in res.get("Vulnerabilities", []) or []:
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
        elif file.name in ["checkov_tf.json", "checkov_k8s.json"]:
            tool_name = file.name.replace(".json", "")
            for f in data.get("results", {}).get("failed_checks", []) or []:
                sev = (f.get("severity") or "LOW").upper()
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
    unique = {}
    for f in findings:
        fp = fingerprint(f)
        if fp not in unique:
            unique[fp] = f

    results = list(unique.values())

    for i, f in enumerate(results):
        f["id"] = i

    return results

# ------------------------------------------------------------
# Executive Summary
# ------------------------------------------------------------

def print_executive_summary(findings):

    total = len(findings)
    sev_counter = Counter([f["severity"] for f in findings])

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
    print(f"Severity Mode            : {SEVERITY_MODE.upper()}")
    print(f"Policy Threshold         : {MIN_SEVERITY}")
    print("-" * 120)
    print(f"Total Vulnerabilities    : {total}")
    print(f"Critical                 : {critical}")
    print(f"High                     : {high}")
    print(f"Medium                   : {medium}")
    print(f"Low                      : {low}")
    print("-" * 120)
    print(f"Overall Risk Posture     : {risk_level}")
    print("=" * 120 + "\n")

# ------------------------------------------------------------
# Full Inventory
# ------------------------------------------------------------

def print_full_inventory(findings):

    print("=" * 120)
    print("FULL VULNERABILITY INVENTORY")
    print("=" * 120)

    print(f"{'Severity':10} | {'Tool':15} | {'Rule/CVE':20} | {'File':40} | Line")
    print("-" * 120)

    for f in findings:
        print(
            f"{f['severity']:10} | "
            f"{f['tool']:15} | "
            f"{(f.get('rule') or '')[:20]:20} | "
            f"{(f.get('file') or '')[:40]:40} | "
            f"{f.get('line')}"
        )

    print("=" * 120 + "\n")

# ------------------------------------------------------------
# Threshold Aggregated Summary
# ------------------------------------------------------------

def print_threshold_summary(findings):

    tool_stats = {}
    tool_cve_map = defaultdict(list)

    for f in findings:
        tool = f["tool"]
        sev = f["severity"]
        rule = f.get("rule", "")
        file = f.get("file", "")

        if tool not in tool_stats:
            tool_stats[tool] = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        tool_stats[tool]["total"] += 1
        tool_stats[tool][sev] += 1

        if rule:
            tool_cve_map[tool].append(f"{rule} : {file}")

    print("=" * 120)
    print(f"AGGREGATED SCAN SUMMARY (MIN_SEVERITY = {MIN_SEVERITY})")
    print("=" * 120)

    print(f"{'Tool':15} | {'Total':5} | {'Critical':8} | {'High':5} | {'Medium':7} | {'Low':4}")

    for tool, stats in tool_stats.items():
        print(
            f"{tool:15} | "
            f"{stats['total']:5} | "
            f"{stats['CRITICAL']:8} | "
            f"{stats['HIGH']:5} | "
            f"{stats['MEDIUM']:7} | "
            f"{stats['LOW']:4}"
        )

    print("=" * 120 + "\n")

# ------------------------------------------------------------
# Deterministic Fallback
# ------------------------------------------------------------

def deterministic_analysis(v):
    return {
        "technical_explanation": f"{v['rule']} detected by {v['tool']}.",
        "business_impact": "Potential exploitation risk.",
        "remediation_steps": "Upgrade component or fix configuration.",
        "risk_score": 8 if v["severity"] in ["CRITICAL","HIGH"] else 5
    }

# ------------------------------------------------------------
# Batched LLM Enrichment
# ------------------------------------------------------------

def batch_enrich(findings):

    if not LLM_ENABLED or not findings:
        for f in findings:
            f["ai_analysis"] = deterministic_analysis(f)
        return findings

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""
Return enriched JSON array with SAME IDs.
Keys:
id
technical_explanation
business_impact
remediation_steps
risk_score

Vulnerabilities:
{json.dumps(findings, indent=2)}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )

        enriched = extract_json(response.choices[0].message.content.strip())
        enriched_map = {e["id"]: e for e in enriched if "id" in e}

        for f in findings:
            f["ai_analysis"] = enriched_map.get(f["id"], deterministic_analysis(f))

    except Exception as e:
        print("⚠ LLM enrichment failed:", e)
        for f in findings:
            f["ai_analysis"] = deterministic_analysis(f)

    return findings

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    print("Collecting findings...")
    findings = parse_reports()

    print_executive_summary(findings)
    print_full_inventory(findings)
    print_threshold_summary(findings)

    print(f"{len(findings)} vulnerabilities matching policy.")

    enriched = batch_enrich(findings)

    (OUTPUT_DIR / "ai_security_intelligence.json").write_text(
        json.dumps(enriched, indent=2)
    )

    print("AI Security Intelligence V4 generated successfully.")

if __name__ == "__main__":
    main()