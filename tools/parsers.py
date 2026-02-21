# tools/parsers.py
"""
Parser Layer
------------
Responsible for:
✔ Converting scanner output → normalized findings
✔ Severity normalization
✔ Defensive JSON handling
✔ Minimal schema mapping

NOTE:
❌ No risk reasoning
❌ No remediation suggestions
❌ No autofix logic
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


# =====================================================
# JSON loader
# =====================================================
def _load_json(path: Path) -> Optional[Any]:
    """Safely load JSON file and return parsed data or None."""
    try:
        txt = path.read_text(encoding="utf-8")
        if not txt or not txt.strip():
            return None
        return json.loads(txt)
    except Exception:
        return None


# =====================================================
# Severity normalization
# =====================================================
def _sev_norm(s: Any) -> str:
    """Normalize tool-specific severity into canonical severity."""
    s = str(s or "").strip().lower()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("high", "error"):
        return "high"
    if s in ("medium", "moderate", "warn", "warning"):
        return "medium"
    if s in ("low", "info", "information"):
        return "low"
    return "low"


# =====================================================
# Utility helpers
# =====================================================
def _split_location(loc: str) -> Tuple[str, Optional[int]]:
    """Split 'file:line' string into file and line."""
    if not isinstance(loc, str) or ":" not in loc:
        return (loc or "", None)
    try:
        parts = loc.split(":")
        return ":".join(parts[:-1]), int(parts[-1])
    except Exception:
        return (loc, None)


def _join_code_lines(lines: Any, max_len: int = 1200) -> str:
    """Convert structured code snippet lines into plain string."""
    try:
        if isinstance(lines, list) and lines and isinstance(lines[0], dict):
            s = "\n".join(str(x.get("Content", "")) for x in lines)
        elif isinstance(lines, str):
            s = lines
        else:
            s = ""
    except Exception:
        s = ""
    return s[:max_len]


# =====================================================
# SEMGREP
# =====================================================
def parse_semgrep(path: Path) -> List[Dict[str, Any]]:
    """Parse Semgrep JSON into normalized findings."""
    data = _load_json(path)
    if not data:
        return []

    results = data.get("results", []) if isinstance(data, dict) else data
    out = []

    for r in results:
        sev = _sev_norm((r.get("extra") or {}).get("severity") or r.get("severity"))
        fid = (r.get("check_id") or r.get("id") or "SEM").upper()
        title = (r.get("extra") or {}).get("message") or r.get("message") or "Issue"

        snippet = _join_code_lines((r.get("extra") or {}).get("lines"))

        out.append({
            "source": "semgrep",
            "tool": "semgrep",
            "id": fid,
            "rule_id": fid,
            "title": title,
            "summary": title,
            "severity": sev,
            "file": r.get("path"),
            "line": (r.get("start") or {}).get("line"),
            "snippet": snippet,
            "category": "code",
            "raw": r,
        })
    return out


# =====================================================
# TRIVY FS / IMAGE
# =====================================================
def _parse_trivy_common(data, source_name, category):
    """Shared parser logic for Trivy FS and Image scans."""
    out = []
    for res in data.get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []):
            out.append({
                "source": source_name,
                "tool": source_name,
                "id": v.get("VulnerabilityID"),
                "title": v.get("Title"),
                "summary": v.get("Title"),
                "severity": _sev_norm(v.get("Severity")),
                "file": target,
                "line": None,
                "snippet": "",
                "category": category,
                "raw": v,
            })
    return out


def parse_trivy_fs(path: Path) -> List[Dict[str, Any]]:
    """Parse Trivy filesystem scan."""
    data = _load_json(path)
    return _parse_trivy_common(data, "trivy_fs", "infra") if data else []


def parse_trivy_image(path: Path) -> List[Dict[str, Any]]:
    """Parse Trivy container image scan."""
    data = _load_json(path)
    return _parse_trivy_common(data, "trivy_image", "image") if data else []


# =====================================================
# TFSEC
# =====================================================
def parse_tfsec(path: Path) -> List[Dict[str, Any]]:
    """Parse tfsec IaC scan output."""
    data = _load_json(path)
    if not data:
        return []

    return [{
        "source": "tfsec",
        "tool": "tfsec",
        "id": r.get("rule_id"),
        "title": r.get("description"),
        "summary": r.get("description"),
        "severity": _sev_norm(r.get("severity")),
        "file": (r.get("location") or {}).get("filename"),
        "line": (r.get("location") or {}).get("start_line"),
        "snippet": "",
        "category": "infra",
        "raw": r,
    } for r in data.get("results", [])]


# =====================================================
# GITLEAKS
# =====================================================
def parse_gitleaks(path: Path) -> List[Dict[str, Any]]:
    """Parse Gitleaks secrets scan output."""
    data = _load_json(path)
    if not isinstance(data, list):
        return []

    return [{
        "source": "gitleaks",
        "tool": "gitleaks",
        "id": item.get("RuleID"),
        "title": item.get("Description"),
        "summary": item.get("Description"),
        "severity": "high",
        "file": item.get("File"),
        "line": item.get("StartLine"),
        "snippet": "[redacted]",
        "category": "secrets",
        "raw": item,
    } for item in data]


# =====================================================
# DEPENDENCY CHECK
# =====================================================
def parse_dependency_check(path: Path) -> List[Dict[str, Any]]:
    """Parse OWASP Dependency Check SCA output."""
    data = _load_json(path)
    if not data:
        return []

    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []):
            sev = _sev_norm(
                v.get("severity")
                or v.get("cvssv3", {}).get("baseSeverity")
                or v.get("cvssV3", {}).get("baseSeverity")
                or v.get("cvssv2", {}).get("baseSeverity")
            )
            out.append({
                "source": "dependency_check",
                "tool": "dependency_check",
                "id": v.get("name"),
                "title": v.get("description"),
                "summary": v.get("description"),
                "severity": sev,
                "file": dep.get("fileName"),
                "line": None,
                "snippet": "",
                "category": "sca",
                "raw": v,
            })
    return out


# =====================================================
# SPOTBUGS
# =====================================================
def parse_spotbugs(path: Path) -> List[Dict[str, Any]]:
    """Parse SpotBugs SAST output."""
    data = _load_json(path)
    if not data:
        return []

    out = []
    for bug in data.get("BugCollection", {}).get("BugInstance", []):
        priority = str(bug.get("priority"))
        sev = "high" if priority == "1" else "medium" if priority == "2" else "low"

        out.append({
            "source": "spotbugs",
            "tool": "spotbugs",
            "id": bug.get("type"),
            "title": bug.get("ShortMessage"),
            "summary": bug.get("LongMessage"),
            "severity": sev,
            "file": (bug.get("SourceLine") or {}).get("sourcepath"),
            "line": (bug.get("SourceLine") or {}).get("start"),
            "snippet": "",
            "category": "code",
            "raw": bug,
        })
    return out


# =====================================================
# CONFTST
# =====================================================
def parse_conftest(path: Path) -> List[Dict[str, Any]]:
    """Parse Conftest policy scan output."""
    data = _load_json(path)
    if not data:
        return []

    out = []
    for res in data:
        for fail in res.get("failures", []):
            out.append({
                "source": "conftest",
                "tool": "conftest",
                "id": fail.get("rule"),
                "title": fail.get("msg"),
                "summary": fail.get("msg"),
                "severity": "high",
                "file": res.get("filename"),
                "line": None,
                "snippet": "",
                "category": "policy",
                "raw": fail,
            })
    return out


# =====================================================
# ZAP
# =====================================================
def parse_zap(path: Path) -> List[Dict[str, Any]]:
    """Parse OWASP ZAP DAST scan output."""
    data = _load_json(path)
    if not data:
        return []

    out = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            sev = _sev_norm(alert.get("riskdesc"))

            out.append({
                "source": "zap",
                "tool": "zap",
                "id": alert.get("pluginid"),
                "title": alert.get("alert"),
                "summary": alert.get("alert"),
                "severity": sev,
                "file": site.get("name"),
                "line": None,
                "snippet": alert.get("evidence"),
                "category": "webapp",
                "raw": alert,
            })
    return out