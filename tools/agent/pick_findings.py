#!/usr/bin/env python3
import json
import pathlib
import hashlib
from typing import List, Dict, Any

SEV_ORDER = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}

FINAL_DIR = pathlib.Path("final-reports")


# ============================================================
# Utilities
# ============================================================

def _load(filename: str) -> Dict[str, Any] | None:
    path = FINAL_DIR / filename
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _want(severity: str, threshold: str) -> bool:
    s = (severity or "").upper()
    t = (threshold or "HIGH").upper()
    return SEV_ORDER.get(s, 0) >= SEV_ORDER.get(t, 2)


def _fingerprint(item: Dict[str, Any]) -> str:
    """
    Create tool-independent fingerprint.
    Used for cross-tool deduplication.
    """
    file = item.get("file", "")
    rule = item.get("rule", "")
    severity = item.get("severity", "")
    detail = (item.get("detail", "") or "")[:200]

    raw = f"{file}|{rule}|{severity}|{detail}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []

    for item in items:
        fp = _fingerprint(item)
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(item)

    return unique


# ============================================================
# Tool Parsers
# ============================================================

def from_semgrep(threshold: str) -> List[Dict[str, Any]]:
    data = _load("semgrep.json") or {}
    findings = []

    for r in data.get("results", []) or []:
        extra = r.get("extra") or {}
        sev = (extra.get("severity") or "LOW").upper()

        if sev == "ERROR":
            sev = "HIGH"
        elif sev == "WARNING":
            sev = "MEDIUM"
        elif sev == "INFO":
            sev = "LOW"

        if not _want(sev, threshold):
            continue

        findings.append({
            "tool": "semgrep",
            "severity": sev,
            "file": r.get("path") or "",
            "line": (r.get("start") or {}).get("line", 0),
            "rule": extra.get("rule_id") or extra.get("engine_rule_id") or "",
            "detail": extra.get("message") or "",
        })

    return findings


def from_checkov_k8s(threshold: str) -> List[Dict[str, Any]]:
    data = _load("checkov_k8s.json") or {}
    findings = []

    for f in (data.get("results", {}) or {}).get("failed_checks", []) or []:
        sev = (f.get("severity") or "LOW").upper()
        if not _want(sev, threshold):
            continue

        findings.append({
            "tool": "checkov_k8s",
            "severity": sev,
            "file": f.get("file_path") or "",
            "line": (f.get("file_line_range") or [0])[0],
            "rule": f.get("check_id") or "",
            "detail": f.get("check_name") or "",
        })

    return findings


def from_checkov_tf(threshold: str) -> List[Dict[str, Any]]:
    data = _load("checkov_tf.json") or {}
    findings = []

    for f in (data.get("results", {}) or {}).get("failed_checks", []) or []:
        sev = (f.get("severity") or "LOW").upper()
        if not _want(sev, threshold):
            continue

        findings.append({
            "tool": "checkov_tf",
            "severity": sev,
            "file": f.get("file_path") or "",
            "line": (f.get("file_line_range") or [0])[0],
            "rule": f.get("check_id") or "",
            "detail": f.get("check_name") or "",
        })

    return findings


def from_trivy_image(threshold: str) -> List[Dict[str, Any]]:
    data = _load("trivy_image.json") or {}
    findings = []

    for result in data.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = (vuln.get("Severity") or "LOW").upper()
            if not _want(sev, threshold):
                continue

            findings.append({
                "tool": "trivy_image",
                "severity": sev,
                "file": "java-pilot-app/Dockerfile",
                "line": 0,
                "rule": vuln.get("VulnerabilityID") or "",
                "detail": f"{vuln.get('PkgName','')} {vuln.get('InstalledVersion','')}",
            })

    return findings


# ============================================================
# Master Entry
# ============================================================

def get_findings(min_severity: str) -> Dict[str, List[Dict[str, Any]]]:

    all_findings = []
    all_findings += from_semgrep(min_severity)
    all_findings += from_checkov_k8s(min_severity)
    all_findings += from_checkov_tf(min_severity)
    all_findings += from_trivy_image(min_severity)

    # Deduplicate across ALL tools
    all_findings = _dedupe(all_findings)

    # Route by file type
    java = [f for f in all_findings if f["file"].endswith(".java")]
    k8s = [f for f in all_findings if f["file"].endswith((".yml", ".yaml"))]
    tf = [f for f in all_findings if f["file"].endswith(".tf")]
    docker = [f for f in all_findings if "Dockerfile" in f["file"]]

    return {
        "java": java,
        "k8s": k8s,
        "tf": tf,
        "docker": docker,
    }



# #!/usr/bin/env python3
# import json
# import pathlib
# from typing import List, Dict, Any

# # ============================================================
# # Severity Model (Single Source of Truth)
# # ============================================================

# SEV_ORDER = {
#     "CRITICAL": 3,
#     "HIGH": 2,
#     "MEDIUM": 1,
#     "LOW": 0,
# }

# FINAL_DIR = pathlib.Path("final-reports")


# def _load(filename: str) -> Dict[str, Any] | None:
#     path = FINAL_DIR / filename
#     if not path.exists():
#         return None
#     try:
#         return json.loads(path.read_text(encoding="utf-8"))
#     except Exception:
#         return None


# def _want(severity: str, threshold: str) -> bool:
#     s = (severity or "").upper()
#     t = (threshold or "HIGH").upper()
#     return SEV_ORDER.get(s, 0) >= SEV_ORDER.get(t, 2)


# # ============================================================
# # Tool Parsers
# # ============================================================

# def from_semgrep(threshold: str) -> List[Dict[str, Any]]:
#     data = _load("semgrep.json") or {}
#     findings = []

#     for r in data.get("results", []) or []:
#         extra = r.get("extra") or {}
#         sev = (extra.get("severity") or "LOW").upper()

#         # Normalize Semgrep severity
#         if sev == "ERROR":
#             sev = "HIGH"
#         elif sev == "WARNING":
#             sev = "MEDIUM"
#         elif sev == "INFO":
#             sev = "LOW"

#         if not _want(sev, threshold):
#             continue

#         path = r.get("path") or ""
#         line = (r.get("start") or {}).get("line", 0)

#         findings.append({
#             "tool": "semgrep",
#             "severity": sev,
#             "file": path,
#             "line": line,
#             "rule": extra.get("rule_id") or extra.get("engine_rule_id") or "",
#             "detail": extra.get("message") or "",
#         })

#     return findings


# def from_checkov_k8s(threshold: str) -> List[Dict[str, Any]]:
#     data = _load("checkov_k8s.json") or {}
#     findings = []

#     for f in (data.get("results", {}) or {}).get("failed_checks", []) or []:
#         sev = (f.get("severity") or "LOW").upper()

#         if not _want(sev, threshold):
#             continue

#         findings.append({
#             "tool": "checkov_k8s",
#             "severity": sev,
#             "file": f.get("file_path") or "",
#             "line": (f.get("file_line_range") or [0])[0],
#             "rule": f.get("check_id") or "",
#             "detail": f.get("check_name") or "",
#         })

#     return findings


# def from_checkov_tf(threshold: str) -> List[Dict[str, Any]]:
#     data = _load("checkov_tf.json") or {}
#     findings = []

#     for f in (data.get("results", {}) or {}).get("failed_checks", []) or []:
#         sev = (f.get("severity") or "LOW").upper()

#         if not _want(sev, threshold):
#             continue

#         findings.append({
#             "tool": "checkov_tf",
#             "severity": sev,
#             "file": f.get("file_path") or "",
#             "line": (f.get("file_line_range") or [0])[0],
#             "rule": f.get("check_id") or "",
#             "detail": f.get("check_name") or "",
#         })

#     return findings


# def from_trivy_image(threshold: str) -> List[Dict[str, Any]]:
#     data = _load("trivy_image.json") or {}
#     findings = []

#     for result in data.get("Results", []) or []:
#         target = result.get("Target") or ""

#         for vuln in result.get("Vulnerabilities") or []:
#             sev = (vuln.get("Severity") or "LOW").upper()

#             if not _want(sev, threshold):
#                 continue

#             findings.append({
#                 "tool": "trivy_image",
#                 "severity": sev,
#                 "file": target,
#                 "line": 0,
#                 "rule": vuln.get("VulnerabilityID") or "",
#                 "detail": f"{vuln.get('PkgName','')} {vuln.get('InstalledVersion','')}",
#             })

#     return findings


# # ============================================================
# # Master Entry
# # ============================================================

# def get_findings(min_severity: str) -> Dict[str, List[Dict[str, Any]]]:
#     """
#     Returns findings grouped by fixer family.
#     Severity filtering handled per tool.
#     """

#     java_findings = from_semgrep(min_severity)
#     k8s_findings = from_checkov_k8s(min_severity)
#     tf_findings = from_checkov_tf(min_severity)
#     docker_findings = from_trivy_image(min_severity)

#     # Strict routing by file extension
#     java_only = [f for f in java_findings if f["file"].endswith(".java")]
#     k8s_only = [f for f in k8s_findings if f["file"].endswith((".yml", ".yaml"))]
#     tf_only = [f for f in tf_findings if f["file"].endswith(".tf")]

#     # Image findings mapped to Dockerfile
#     docker_only = []
#     for f in docker_findings:
#         docker_only.append({
#             **f,
#             "file": "java-pilot-app/Dockerfile"
#         })

#     return {
#         "java": java_only,
#         "k8s": k8s_only,
#         "tf": tf_only,
#         "docker": docker_only,
#     }