
# import json
# from pathlib import Path
# from typing import List, Dict, Any

# def parse_semgrep(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for r in data.get('results', []):
#         sev = (r.get('extra',{}).get('severity','medium') or 'medium').lower()
#         out.append({'source':'semgrep','id':r.get('check_id','SEM').upper(),'title':r.get('extra',{}).get('message','Issue'),'severity':sev})
#     return out

# def parse_trivy_fs(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for res in data.get('Results', []) or []:
#         for v in res.get('Vulnerabilities', []) or []:
#             out.append({'source':'trivy-fs','id':v.get('VulnerabilityID','CVE'),'title':v.get('Title') or v.get('PkgName','Vuln'),'severity':(v.get('Severity','MEDIUM') or 'MEDIUM').lower()})
#         for m in res.get('Misconfigurations', []) or []:
#             out.append({'source':'trivy-misconfig','id':m.get('ID','MIS'),'title':m.get('Title') or m.get('Message','Misconfig'),'severity':(m.get('Severity','MEDIUM') or 'MEDIUM').lower()})
#     return out

# def parse_trivy_image(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for res in data.get('Results', []) or []:
#         for v in res.get('Vulnerabilities', []) or []:
#             out.append({'source':'trivy-image','id':v.get('VulnerabilityID','CVE'),'title':v.get('Title') or v.get('PkgName','Vuln'),'severity':(v.get('Severity','MEDIUM') or 'MEDIUM').lower()})
#     return out

# def parse_tfsec(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for r in data.get('results', []) or []:
#         out.append({'source':'tfsec','id':r.get('rule_id','TFSEC'),'title':r.get('description','tfsec finding'),'severity':(r.get('severity','MEDIUM') or 'MEDIUM').lower()})
#     return out

# def parse_gitleaks(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text() or '[]')
#     out = []
#     for item in data:
#         out.append({'source':'gitleaks','id':item.get('RuleID','SECRET'),'title':item.get('Description','Secret'),'severity':'high'})
#     return out

# def parse_conftest(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for res in data:
#         for fail in res.get('failures', []) or []:
#             out.append({'source':'conftest','id':'POLICY','title':fail.get('msg','Policy violation'),'severity':'high'})
#     return out

# def parse_zap(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists(): return []
#     data = json.loads(path.read_text())
#     out = []
#     for site in data.get('site', []) or []:
#         for alert in site.get('alerts', []) or []:
#             risk = (alert.get('riskdesc','').split(' ')[0] or 'Medium').lower()
#             sev = 'low'
#             if 'high' in risk: sev='critical'
#             elif 'medium' in risk: sev='medium'
#             elif 'low' in risk: sev='low'
#             out.append({'source':'zap','id':alert.get('pluginid','ZAP'),'title':alert.get('alert','ZAP Alert'),'severity':sev})
#     return out




#imp
# # tools/parsers.py
# import json
# from pathlib import Path
# from typing import List, Dict, Any, Optional


# def _load_json(path: Path) -> Optional[Any]:
#     """Safe JSON loader. Returns None for empty/malformed content."""
#     try:
#         txt = path.read_text(encoding="utf-8")
#         if not txt.strip():
#             return None
#         return json.loads(txt)
#     except Exception:
#         return None


# def _sev_norm(s: str) -> str:
#     s = (s or "").strip().lower()
#     if s in ("critical", "crit"):
#         return "critical"
#     if s in ("high", "error"):
#         return "high"
#     if s in ("medium", "moderate", "warn", "warning"):
#         return "medium"
#     if s in ("low", "info", "information"):
#         return "low"
#     return "low"


# # --------------------------
# # Semgrep (JSON)
# # Supports classic Semgrep JSON (with `extra`, `check_id`, `path`, `start.line`)
# # and simplified schema like the one you shared (`severity`, `location`, `tool`, `id`, `message`)
# # --------------------------
# def parse_semgrep(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     for r in data.get("results", []) or []:
#         # --- Try simplified schema first (like your example) ---
#         # {
#         #   "severity": "high",
#         #   "category": "code",
#         #   "location": "app/main.py:12",
#         #   "tool": "semgrep",
#         #   "id": "TEST001",
#         #   "message": "Hardcoded password detected"
#         # }
#         if any(k in r for k in ("severity", "location", "message", "tool", "id")) and not r.get("extra"):
#             sev = _sev_norm(r.get("severity", "medium"))
#             title = r.get("message", "Issue")
#             fid = (r.get("id") or "SEM").upper()
#             loc = r.get("location", "")
#             category = (r.get("category") or "code").lower()

#             finding = {
#                 "source": "semgrep",
#                 "id": fid,
#                 "title": title,
#                 "severity": sev,
#                 "tool": r.get("tool", "semgrep"),
#                 "message": title,
#                 "location": loc,
#                 "category": category,
#                 "raw": r,
#             }
#             out.append(finding)
#             continue

#         # --- Classic Semgrep JSON shape ---
#         sev = _sev_norm((r.get("extra", {}) or {}).get("severity", "medium"))
#         title = (r.get("extra", {}) or {}).get("message", "Issue")
#         fid = (r.get("check_id", "SEM") or "SEM").upper()

#         # File path and line
#         file_path = r.get("path") or (r.get("location", {}) or {}).get("path")
#         line = None
#         if isinstance(r.get("start"), dict):
#             line = r.get("start", {}).get("line")
#         elif isinstance((r.get("extra", {}) or {}).get("lines"), str):
#             line = r["extra"]["lines"]
#         loc = f"{file_path}:{line}" if file_path and line else (file_path or "")

#         finding = {
#             "source": "semgrep",
#             "id": fid,
#             "title": title,
#             "severity": sev,
#             "tool": "semgrep",
#             "message": title,
#             "location": loc,
#             "category": "code",
#             "raw": r,
#         }
#         out.append(finding)
#     return out


# # --------------------------
# # Trivy FS (JSON)
# # --------------------------
# def parse_trivy_fs(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     for res in data.get("Results", []) or []:
#         target = res.get("Target", "")

#         # Vulnerabilities
#         for v in res.get("Vulnerabilities", []) or []:
#             sev = _sev_norm(v.get("Severity", "MEDIUM"))
#             title = v.get("Title") or v.get("Description") or v.get("PkgName", "Vuln")
#             fid = v.get("VulnerabilityID", "CVE")

#             out.append(
#                 {
#                     "source": "trivy-fs",
#                     "id": fid,
#                     "title": title,
#                     "severity": sev,
#                     "tool": "trivy-fs",
#                     "message": title,
#                     "location": target,
#                     "category": "infra",
#                     "raw": v,
#                 }
#             )

#         # Misconfigurations
#         for m in res.get("Misconfigurations", []) or []:
#             sev = _sev_norm(m.get("Severity", "MEDIUM"))
#             title = m.get("Title") or m.get("Message", "Misconfig")
#             fid = m.get("ID", "MIS")

#             out.append(
#                 {
#                     "source": "trivy-misconfig",
#                     "id": fid,
#                     "title": title,
#                     "severity": sev,
#                     "tool": "trivy-fs",
#                     "message": title,
#                     "location": target,
#                     "category": "infra",
#                     "raw": m,
#                 }
#             )
#     return out


# # --------------------------
# # Trivy Image (JSON)
# # --------------------------
# def parse_trivy_image(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     for res in data.get("Results", []) or []:
#         target = res.get("Target", "")
#         for v in res.get("Vulnerabilities", []) or []:
#             sev = _sev_norm(v.get("Severity", "MEDIUM"))
#             title = v.get("Title") or v.get("Description") or v.get("PkgName", "Vuln")
#             fid = v.get("VulnerabilityID", "CVE")

#             out.append(
#                 {
#                     "source": "trivy-image",
#                     "id": fid,
#                     "title": title,
#                     "severity": sev,
#                     "tool": "trivy-image",
#                     "message": title,
#                     "location": target,
#                     "category": "image",
#                     "raw": v,
#                 }
#             )
#     return out


# # --------------------------
# # tfsec (JSON)
# # --------------------------
# def parse_tfsec(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     for r in data.get("results", []) or []:
#         sev = _sev_norm(r.get("severity", "MEDIUM"))
#         title = r.get("description", "tfsec finding")
#         fid = r.get("rule_id", "TFSEC")
#         filename = (r.get("location") or {}).get("filename", "")

#         out.append(
#             {
#                 "source": "tfsec",
#                 "id": fid,
#                 "title": title,
#                 "severity": sev,
#                 "tool": "tfsec",
#                 "message": title,
#                 "location": filename,
#                 "category": "infra",
#                 "raw": r,
#             }
#         )
#     return out


# # --------------------------
# # gitleaks (JSON list)
# # --------------------------
# def parse_gitleaks(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     if isinstance(data, list):
#         for item in data:
#             file_path = item.get("File") or ""
#             start_line = item.get("StartLine")
#             loc = f"{file_path}:{start_line}" if file_path and start_line else file_path

#             out.append(
#                 {
#                     "source": "gitleaks",
#                     "id": item.get("RuleID", "SECRET"),
#                     "title": item.get("Description", "Secret"),
#                     "severity": "high",  # secrets default to high
#                     "tool": "gitleaks",
#                     "message": item.get("Description", "Secret"),
#                     "location": loc,
#                     "category": "secrets",
#                     "raw": item,
#                 }
#             )
#     return out


# # --------------------------
# # Conftest (OPA) (JSON)
# # Supports list of results or {"files":[...]} shapes
# # --------------------------
# def parse_conftest(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     iterable = []
#     if isinstance(data, list):
#         iterable = data
#     elif isinstance(data, dict):
#         iterable = data.get("files", []) or []

#     for res in iterable:
#         filename = res.get("filename") or res.get("file") or ""
#         failures = res.get("failures") or res.get("failures_details") or []
#         for fail in failures:
#             msg = fail.get("msg") or fail.get("message") or "Policy violation"
#             rule = fail.get("rule") or (fail.get("metadata") or {}).get("id") or "POLICY"
#             sev = _sev_norm((fail.get("metadata") or {}).get("severity", "high"))

#             out.append(
#                 {
#                     "source": "conftest",
#                     "id": rule,
#                     "title": msg,
#                     "severity": sev,
#                     "tool": "conftest",
#                     "message": msg,
#                     "location": filename,
#                     "category": "policy",
#                     "raw": fail,
#                 }
#             )
#     return out


# # --------------------------
# # OWASP ZAP Baseline (-J zap.json)
# # --------------------------
# def parse_zap(path: Path) -> List[Dict[str, Any]]:
#     if not path.exists():
#         return []
#     data = _load_json(path)
#     if not data:
#         return []
#     out: List[Dict[str, Any]] = []

#     for site in data.get("site", []) or []:
#         site_name = site.get("name") or ""
#         for alert in site.get("alerts", []) or []:
#             risk = ((alert.get("riskdesc", "") or "").split(" ") or [""])[0].lower()
#             if "high" in risk:
#                 sev = "critical"  # treat ZAP 'High' as 'critical' to be strict
#             elif "medium" in risk:
#                 sev = "medium"
#             elif "low" in risk:
#                 sev = "low"
#             else:
#                 sev = "low"

#             out.append(
#                 {
#                     "source": "zap",
#                     "id": alert.get("pluginid", "ZAP"),
#                     "title": alert.get("alert", "ZAP Alert"),
#                     "severity": sev,
#                     "tool": "zap",
#                     "message": alert.get("alert", "ZAP Alert"),
#                     "location": site_name,
#                     "category": "webapp",
#                     "raw": alert,
#                 }
#             )
#     return out








#chck
# tools/parsers.py
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


def _load_json(path: Path) -> Optional[Any]:
    """Safe JSON loader. Returns None for empty/malformed content."""
    try:
        txt = path.read_text(encoding="utf-8")
        if not txt or not txt.strip():
            return None
        return json.loads(txt)
    except Exception:
        return None


def _sev_norm(s: Any) -> str:
    """Normalize severities into: low | medium | high | critical."""
    if isinstance(s, str):
        s = s.strip().lower()
    else:
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


def _split_location(loc: str) -> Tuple[str, Optional[int]]:
    """
    Try to split a 'file:line' location string into (file, line).
    Returns (file, None) if line is not present or parseable.
    """
    if not isinstance(loc, str) or ":" not in loc:
        return (loc or "", None)
    file_part, line_part = loc, None
    try:
        parts = loc.split(":")
        if len(parts) >= 2:
            # in case path also has colons (e.g., Windows drive in logs)
            file_part = ":".join(parts[:-1])
            line_part = int(parts[-1])
    except Exception:
        line_part = None
    return (file_part, line_part)


def _join_code_lines(lines: Any, max_len: int = 1200) -> str:
    """
    Best-effort join of a code block from tool-provided structures.
    Truncates to max_len to keep prompts compact.

    Example: Trivy CauseMetadata.Code.Lines → [{'Number':..., 'Content':...}, ...]
    """
    try:
        # Trivy CauseMetadata.Code.Lines -> [{'Number':..., 'Content':...}, ...]
        if isinstance(lines, list) and lines and isinstance(lines[0], dict):
            s = "\n".join(str(x.get("Content", "")) for x in lines)
        elif isinstance(lines, str):
            s = lines
        else:
            s = ""
    except Exception:
        s = ""
    s = s.strip()
    return s if len(s) <= max_len else (s[:max_len] + "\n... [truncated] ...")


# --------------------------
# Semgrep (JSON)
# Supports classic Semgrep JSON (with `extra`, `check_id`, `path`, `start.line`)
# and simplified schema like your example (`severity`, `location`, `tool`, `id`, `message`)
# --------------------------
def parse_semgrep(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    # If someone passed a list (non-standard), treat each item as a result dict
    results = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

    for r in results or []:
        # --- Try simplified schema first ---
        # {
        #   "severity": "high",
        #   "category": "code",
        #   "location": "app/main.py:12",
        #   "tool": "semgrep",
        #   "id": "TEST001",
        #   "message": "Hardcoded password detected"
        # }
        if any(k in r for k in ("severity", "location", "message", "tool", "id")) and not r.get("extra"):
            sev = _sev_norm(r.get("severity", "medium"))
            title = r.get("message", "Issue")
            fid = (r.get("id") or r.get("rule_id") or "SEM").upper()
            loc = r.get("location", "")
            file_path, line_num = _split_location(loc)
            category = (r.get("category") or "code").lower()
            snippet = r.get("snippet") or ""  # if upstream has provided one

            finding = {
                "source": "semgrep",
                "id": fid,
                "rule_id": fid,
                "title": title,
                "summary": title,
                "severity": sev,
                "tool": r.get("tool", "semgrep"),
                "message": title,
                "location": loc,
                "file": file_path,
                "line": line_num,
                "snippet": snippet,
                "category": category,
                "raw": r,
            }
            out.append(finding)
            continue

        # --- Classic Semgrep JSON shape ---
        sev = _sev_norm((r.get("extra", {}) or {}).get("severity", "medium"))
        title = (r.get("extra", {}) or {}).get("message", "Issue")
        fid = (r.get("check_id", "SEM") or "SEM").upper()

        # File path and line
        file_path = r.get("path") or (r.get("location", {}) or {}).get("path") or ""
        line = None
        if isinstance(r.get("start"), dict):
            try:
                line = int(r.get("start", {}).get("line"))
            except Exception:
                line = r.get("start", {}).get("line")
        # Snippet from extra.lines (string) if present
        snippet = ""
        try:
            lines = (r.get("extra", {}) or {}).get("lines")
            if isinstance(lines, str):
                snippet = _join_code_lines(lines)
        except Exception:
            snippet = ""

        loc = f"{file_path}:{line}" if file_path and line else (file_path or "")

        finding = {
            "source": "semgrep",
            "id": fid,
            "rule_id": fid,
            "title": title,
            "summary": title,
            "severity": sev,
            "tool": "semgrep",
            "message": title,
            "location": loc,
            "file": file_path,
            "line": line,
            "snippet": snippet,
            "category": "code",
            "raw": r,
        }
        out.append(finding)
    return out


# --------------------------
# Trivy FS (JSON)
# --------------------------
def parse_trivy_fs(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    for res in data.get("Results", []) or []:
        target = res.get("Target", "")  # file or directory

        # Vulnerabilities
        for v in res.get("Vulnerabilities", []) or []:
            sev = _sev_norm(v.get("Severity", "MEDIUM"))
            title = v.get("Title") or v.get("Description") or v.get("PkgName", "Vuln")
            fid = v.get("VulnerabilityID", "CVE")

            out.append(
                {
                    "source": "trivy-fs",
                    "id": fid,
                    "title": title,
                    "summary": title,
                    "severity": sev,
                    "tool": "trivy-fs",
                    "message": title,
                    "location": target,
                    "file": target,
                    "line": None,
                    "snippet": "",  # Trivy vuln reports typically don't include code/context
                    "category": "infra",
                    "raw": v,
                }
            )

        # Misconfigurations
        for m in res.get("Misconfigurations", []) or []:
            sev = _sev_norm(m.get("Severity", "MEDIUM"))
            title = m.get("Title") or m.get("Message", "Misconfig")
            fid = m.get("ID", "MIS")

            # Try to extract code context if available
            cause = m.get("CauseMetadata") or {}
            code_block = (cause.get("Code") or {}).get("Lines")
            snippet = _join_code_lines(code_block) if code_block else ""

            out.append(
                {
                    "source": "trivy-misconfig",
                    "id": fid,
                    "title": title,
                    "summary": title,
                    "severity": sev,
                    "tool": "trivy-fs",
                    "message": title,
                    "location": target,
                    "file": target,
                    "line": None,  # Start/End lines can be added if present in CauseMetadata
                    "snippet": snippet,
                    "category": "infra",
                    "raw": m,
                }
            )
    return out


# --------------------------
# Trivy Image (JSON)
# --------------------------
def parse_trivy_image(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    for res in data.get("Results", []) or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            sev = _sev_norm(v.get("Severity", "MEDIUM"))
            title = v.get("Title") or v.get("Description") or v.get("PkgName", "Vuln")
            fid = v.get("VulnerabilityID", "CVE")

            out.append(
                {
                    "source": "trivy-image",
                    "id": fid,
                    "title": title,
                    "summary": title,
                    "severity": sev,
                    "tool": "trivy-image",
                    "message": title,
                    "location": target,
                    "file": target,
                    "line": None,
                    "snippet": "",
                    "category": "image",
                    "raw": v,
                }
            )
    return out


# --------------------------
# tfsec (JSON)
# --------------------------
def parse_tfsec(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    for r in data.get("results", []) or []:
        sev = _sev_norm(r.get("severity", "MEDIUM"))
        title = r.get("description", "tfsec finding")
        fid = r.get("rule_id", "TFSEC")
        filename = (r.get("location") or {}).get("filename", "") or r.get("filepath") or ""
        # Try lines (tfsec v1 often has start_line/end_line, or in range{})
        line = (r.get("location") or {}).get("start_line") or (r.get("range") or {}).get("startLine")

        out.append(
            {
                "source": "tfsec",
                "id": fid,
                "title": title,
                "summary": title,
                "severity": sev,
                "tool": "tfsec",
                "message": title,
                "location": filename,
                "file": filename,
                "line": line,
                "snippet": "",  # tfsec JSON typically doesn't include full code
                "category": "infra",
                "raw": r,
            }
        )
    return out


# --------------------------
# gitleaks (JSON list)
# --------------------------
def parse_gitleaks(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    if isinstance(data, list):
        for item in data:
            file_path = item.get("File") or ""
            start_line = item.get("StartLine")
            loc = f"{file_path}:{start_line}" if file_path and start_line else file_path

            # REDACT snippet to avoid leaking sensitive content in artifacts/PRs
            snippet = "[redacted secret value]"

            out.append(
                {
                    "source": "gitleaks",
                    "id": item.get("RuleID", "SECRET"),
                    "title": item.get("Description", "Secret"),
                    "summary": item.get("Description", "Secret"),
                    "severity": "high",  # secrets default to high
                    "tool": "gitleaks",
                    "message": item.get("Description", "Secret"),
                    "location": loc,
                    "file": file_path,
                    "line": start_line,
                    "snippet": snippet,
                    "category": "secrets",
                    "raw": item,
                }
            )
    return out


# --------------------------
# Conftest (OPA) (JSON)
# Supports list of results or {"files":[...]} shapes
# --------------------------
def parse_conftest(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    iterable = []
    if isinstance(data, list):
        iterable = data
    elif isinstance(data, dict):
        iterable = data.get("files", []) or []

    for res in iterable:
        filename = res.get("filename") or res.get("file") or ""
        failures = res.get("failures") or res.get("failures_details") or []
        for fail in failures:
            msg = fail.get("msg") or fail.get("message") or "Policy violation"
            rule = fail.get("rule") or (fail.get("metadata") or {}).get("id") or "POLICY"
            sev = _sev_norm((fail.get("metadata") or {}).get("severity", "high"))

            out.append(
                {
                    "source": "conftest",
                    "id": rule,
                    "title": msg,
                    "summary": msg,
                    "severity": sev,
                    "tool": "conftest",
                    "message": msg,
                    "location": filename,
                    "file": filename,
                    "line": None,
                    "snippet": "",  # OPA output usually doesn't include source snippet here
                    "category": "policy",
                    "raw": fail,
                }
            )
    return out


# --------------------------
# OWASP ZAP Baseline (-J zap.json)
# --------------------------
def parse_zap(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    data = _load_json(path)
    if not data:
        return []
    out: List[Dict[str, Any]] = []

    for site in data.get("site", []) or []:
        site_name = site.get("name") or ""
        for alert in site.get("alerts", []) or []:
            risk = ((alert.get("riskdesc", "") or "").split(" ") or [""])[0].lower()
            if "high" in risk:
                sev = "critical"  # treat ZAP 'High' as 'critical' to be strict
            elif "medium" in risk:
                sev = "medium"
            elif "low" in risk:
                sev = "low"
            else:
                sev = "low"

            snippet = alert.get("evidence") or ""

            out.append(
                {
                    "source": "zap",
                    "id": alert.get("pluginid", "ZAP"),
                    "title": alert.get("alert", "ZAP Alert"),
                    "summary": alert.get("alert", "ZAP Alert"),
                    "severity": sev,
                    "tool": "zap",
                    "message": alert.get("alert", "ZAP Alert"),
                    "location": site_name,
                    "file": site_name,  # web target; not a file path but useful for grouping
                    "line": None,
                    "snippet": snippet,
                    "category": "webapp",
                    "raw": alert,
                }
            )
    return out

