#!/usr/bin/env python3
import json, pathlib, os
from typing import List, Dict, Any

SEV_ORDER = {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}

FINAL_DIR = pathlib.Path("final-reports")

def _load(fn: str):
    p = FINAL_DIR/fn
    if not p.exists(): return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def _want(sev: str, threshold: str) -> bool:
    s = (sev or "").upper()
    return SEV_ORDER.get(s,0) >= SEV_ORDER.get(threshold.upper(), 2)

def from_checkov_k8s(threshold: str) -> List[Dict[str,Any]]:
    d = _load("checkov_k8s.json") or {}
    out = []
    for f in (d.get("results",{}) or {}).get("failed_checks",[]) or []:
        sev = (f.get("severity") or "LOW").upper()
        if not _want(sev, threshold): continue
        out.append({
            "tool":"checkov_k8s",
            "severity": sev,
            "file": f.get("file_path") or "",
            "line": f.get("file_line_range",[0])[0] if f.get("file_line_range") else 0,
            "rule": f.get("check_id"),
            "detail": f.get("check_name") or ""
        })
    return out

def from_checkov_tf(threshold: str) -> List[Dict[str,Any]]:
    d = _load("checkov_tf.json") or {}
    out = []
    for f in (d.get("results",{}) or {}).get("failed_checks",[]) or []:
        sev = (f.get("severity") or "LOW").upper()
        if not _want(sev, threshold): continue
        out.append({
            "tool":"checkov_tf",
            "severity": sev,
            "file": f.get("file_path") or "",
            "line": f.get("file_line_range",[0])[0] if f.get("file_line_range") else 0,
            "rule": f.get("check_id"),
            "detail": f.get("check_name") or ""
        })
    return out

def from_semgrep(threshold: str) -> List[Dict[str,Any]]:
    d = _load("semgrep.json") or {}
    out=[]
    for r in d.get("results",[]) or []:
        sev = ((r.get("extra") or {}).get("severity") or "LOW").upper()
        # map ERROR->HIGH, WARNING->MEDIUM, INFO->LOW
        if sev == "ERROR": sev="HIGH"
        elif sev == "WARNING": sev="MEDIUM"
        elif sev == "INFO": sev="LOW"
        if not _want(sev, threshold): continue
        path = r.get("path") or ""
        start = ((r.get("start") or {}).get("line")) or ((r.get("start",{}).get("location") or {}).get("line")) or 0
        rule = ((r.get("extra") or {}).get("rule_id")) or ((r.get("extra") or {}).get("engine_rule_id")) or ""
        out.append({
            "tool":"semgrep",
            "severity": sev,
            "file": path,
            "line": start,
            "rule": rule,
            "detail": (r.get("extra") or {}).get("message") or ""
        })
    return out

def from_trivy_image(threshold: str) -> List[Dict[str,Any]]:
    d = _load("trivy_image.json") or {}
    out=[]
    for r in d.get("Results",[]) or []:
        target = r.get("Target") or ""
        for v in r.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "LOW").upper()
            if not _want(sev, threshold): continue
            out.append({
                "tool":"trivy_image",
                "severity": sev,
                "file": target,
                "line": 0,
                "rule": v.get("VulnerabilityID") or "",
                "detail": f"{v.get('PkgName','')} {v.get('InstalledVersion','')}"
            })
    return out

def get_findings(min_severity: str) -> Dict[str, List[Dict[str,Any]]]:
    """Return findings grouped by fixer family."""
    k8s = from_checkov_k8s(min_severity)
    tf  = from_checkov_tf(min_severity)
    java= from_semgrep(min_severity)
    img = from_trivy_image(min_severity)

    # Simple routing by file/type
    k8s_only = [f for f in k8s if f["file"].endswith((".yml",".yaml"))]
    tf_only  = [f for f in tf  if f["file"].endswith(".tf")]
    java_only= [f for f in java if f["file"].endswith(".java")]
    dock = [{"file": "java-pilot-app/Dockerfile", **f} for f in img]
    # dock     = img  # we’ll drive Docker best‑practice from image results

    return {"k8s": k8s_only, "tf": tf_only, "java": java_only, "docker": dock}