# tools/parsers.py
"""
Enterprise JSON parsers for security tools.

Safe, deterministic, CI-ready.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional


# -------------------------------------------------
# Utilities
# -------------------------------------------------

def _load_json(path: Path) -> Optional[Any]:
    try:
        if not path.exists():
            return None
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return None
        return json.loads(text)
    except Exception:
        return None


def _norm_sev(s: str) -> str:
    s = (s or "").lower()
    if s in ("critical",):
        return "critical"
    if s in ("high",):
        return "high"
    if s in ("medium", "moderate"):
        return "medium"
    return "low"


# -------------------------------------------------
# Semgrep
# -------------------------------------------------

def parse_semgrep(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not data:
        return []

    results = data.get("results", [])
    findings = []

    for r in results:
        findings.append({
            "tool": "semgrep",
            "severity": _norm_sev(r.get("extra", {}).get("severity", "medium")),
            "file": r.get("path"),
            "line": (r.get("start") or {}).get("line"),
            "rule_id": r.get("check_id"),
            "message": r.get("extra", {}).get("message"),
            "category": "code",
        })

    return findings


# -------------------------------------------------
# Trivy FS
# -------------------------------------------------

def parse_trivy_fs(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not data:
        return []

    findings = []

    for res in data.get("Results", []):
        target = res.get("Target")

        for v in res.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy_fs",
                "severity": _norm_sev(v.get("Severity")),
                "file": target,
                "rule_id": v.get("VulnerabilityID"),
                "message": v.get("Title"),
                "category": "infra",
            })

    return findings


# -------------------------------------------------
# tfsec
# -------------------------------------------------

def parse_tfsec(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not data:
        return []

    findings = []

    for r in data.get("results", []):
        findings.append({
            "tool": "tfsec",
            "severity": _norm_sev(r.get("severity")),
            "file": r.get("location", {}).get("filename"),
            "rule_id": r.get("rule_id"),
            "message": r.get("description"),
            "category": "infra",
        })

    return findings


# -------------------------------------------------
# Gitleaks
# -------------------------------------------------

def parse_gitleaks(path: Path) -> List[Dict[str, Any]]:
    data = _load_json(path)
    if not data:
        return []

    findings = []

    for item in data:
        findings.append({
            "tool": "gitleaks",
            "severity": "high",
            "file": item.get("File"),
            "rule_id": item.get("RuleID"),
            "message": item.get("Description"),
            "category": "secrets",
        })

    return findings


# -------------------------------------------------
# Stubs for optional tools
# -------------------------------------------------

def parse_trivy_image(path: Path) -> List[Dict[str, Any]]:
    return []

def parse_conftest(path: Path) -> List[Dict[str, Any]]:
    return []

def parse_zap(path: Path) -> List[Dict[str, Any]]:
    return []