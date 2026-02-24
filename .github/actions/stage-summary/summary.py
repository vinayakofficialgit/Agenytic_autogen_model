#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
from typing import Dict, Tuple, Any, List, Union

Json = Union[Dict[str, Any], List[Any]]

def load_json(path: pathlib.Path) -> Json:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

# ---------- Counters per tool ----------

def count_semgrep(d: Json) -> Tuple[int, Dict[str, int]]:
    if not isinstance(d, dict):
        return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    results = d.get("results", []) or []
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        s = ((r.get("extra") or {}).get("severity") or "").upper()
        if s == "ERROR":
            s = "HIGH"
        elif s == "WARNING":
            s = "MEDIUM"
        elif s == "INFO":
            s = "LOW"
        if s in sev:
            sev[s] += 1
    return sum(sev.values()), sev

def count_spotbugs(d: Json) -> Tuple[int, Dict[str, int]]:
    # Expect JSON converted from XML (BugCollection/BugInstance)
    if not isinstance(d, dict):
        return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    coll = d.get("BugCollection", {}) or {}
    bugs = coll.get("BugInstance", []) or []
    if isinstance(bugs, dict):
        bugs = [bugs]
    for b in bugs:
        # SpotBugs priority: 1=High, 2=Medium, else=Low
        p = str(b.get("@priority") or b.get("priority") or "3")
        if p == "1":
            sev["HIGH"] += 1
        elif p == "2":
            sev["MEDIUM"] += 1
        else:
            sev["LOW"] += 1
    return sum(sev.values()), sev

def count_gitleaks(d: Json) -> Tuple[int, Dict[str, int]]:
    """
    Support:
      1) Top-level array: [ {...}, {...} ]
      2) Object with 'findings' or 'leaks': {'findings': [...]} or {'leaks': [...]}
    If schema lacks severities, count all as HIGH for visibility.
    """
    total = 0
    if isinstance(d, list):
        total = len(d)
    elif isinstance(d, dict):
        arr = d.get("findings")
        if isinstance(arr, list):
            total = len(arr)
        else:
            arr = d.get("leaks")
            total = len(arr) if isinstance(arr, list) else 0
    else:
        total = 0

    sev = {"CRITICAL": 0, "HIGH": total, "MEDIUM": 0, "LOW": 0}
    return total, sev

def count_trivy(d: Json) -> Tuple[int, Dict[str, int]]:
    if not isinstance(d, dict):
        return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for r in d.get("Results", []) or []:
        for v in r.get("Vulnerabilities") or []:
            total += 1
            s = (v.get("Severity") or "").upper()
            if s in sev:
                sev[s] += 1
    return total, sev

def count_checkov(d: Json) -> Tuple[int, Dict[str, int]]:
    if not isinstance(d, dict):
        return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    res = d.get("results", {}) or {}
    failed = res.get("failed_checks") or []
    for f in failed:
        s = (f.get("severity") or "").upper()
        if s in sev:
            sev[s] += 1
    return len(failed), sev

def count_zap(d: Json) -> Tuple[int, Dict[str, int]]:
    if not isinstance(d, dict):
        return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = 0
    for site in d.get("site", []) or []:
        for a in site.get("alerts") or []:
            total += 1
            risk = str(a.get("riskcode", "0"))
            # ZAP: 0=info, 1=low, 2=medium, 3=high → map info→LOW
            if risk == "3":
                sev["HIGH"] += 1
            elif risk == "2":
                sev["MEDIUM"] += 1
            elif risk == "1":
                sev["LOW"] += 1
            else:
                sev["LOW"] += 1
    return total, sev

# ---------- Router by filename ----------

def route(filename: str, data: Json) -> Tuple[int, Dict[str, int]]:
    fn = filename.lower()
    if "semgrep" in fn:
        return count_semgrep(data)
    if "spotbugs" in fn:
        return count_spotbugs(data)
    if "gitleaks" in fn:
        return count_gitleaks(data)
    if "trivy" in fn and "fs" in fn:
        return count_trivy(data)
    if "trivy" in fn and "image" in fn:
        return count_trivy(data)
    if "checkov" in fn:
        return count_checkov(data)
    if "zap" in fn:
        return count_zap(data)
    return 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", required=True)
    ap.add_argument("--reports", required=True)
    ap.add_argument("--files", required=True, help="Comma-separated list of filenames to parse")
    args = ap.parse_args()

    reports_dir = pathlib.Path(args.reports).resolve()
    files = [f.strip() for f in args.files.split(",") if f.strip()]

    rows = []
    generated = []
    for fn in files:
        p = reports_dir / fn
        if p.exists() and p.stat().st_size > 0:
            d = load_json(p)
            t, sev = route(fn, d)
            rows.append((fn, t, sev))
            generated.append(fn)
        else:
            rows.append((fn, 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}))

    md = []
    md.append(f"### {args.stage} — Reports & Severity")
    md.append("")
    md.append("| Report file | Total | Critical | High | Medium | Low |")
    md.append("|-------------|------:|--------:|-----:|------:|----:|")
    for fn, total, sev in rows:
        md.append(f"| `{fn}` | {total} | {sev['CRITICAL']} | {sev['HIGH']} | {sev['MEDIUM']} | {sev['LOW']} |")

    md.append("\n**Files generated:**")
    if generated:
        for g in generated:
            md.append(f"- {g}")
    else:
        md.append("- (none)")

    summary_path = reports_dir / f"{args.stage}-summary.md"
    summary_path.write_text("\n".join(md), encoding="utf-8")

    print("\n".join(md))

    gout = os.environ.get("GITHUB_OUTPUT")
    if gout:
        with open(gout, "a", encoding="utf-8") as f:
            f.write(f"summary_path={summary_path}\n")

if __name__ == "__main__":
    main()



# #!/usr/bin/env python3
# import argparse
# import json
# import os
# import pathlib
# from typing import Dict, Tuple

# def load_json(path: pathlib.Path) -> Dict:
#     try:
#         return json.loads(path.read_text(encoding="utf-8"))
#     except Exception:
#         return {}

# # ---------- Counters per tool ----------

# def count_semgrep(d: Dict) -> Tuple[int, Dict[str, int]]:
#     results = d.get("results", []) or []
#     sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
#     for r in results:
#         s = ((r.get("extra") or {}).get("severity") or "").upper()
#         # Map Semgrep severities to our buckets
#         if s == "ERROR":
#             s = "HIGH"
#         elif s == "WARNING":
#             s = "MEDIUM"
#         elif s == "INFO":
#             s = "LOW"
#         if s in sev:
#             sev[s] += 1
#     return sum(sev.values()), sev

# def count_spotbugs(d: Dict) -> Tuple[int, Dict[str, int]]:
#     # Expect JSON converted from XML (BugCollection/BugInstance)
#     sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
#     coll = d.get("BugCollection", {}) or {}
#     bugs = coll.get("BugInstance", []) or []
#     if isinstance(bugs, dict):
#         bugs = [bugs]
#     for b in bugs:
#         # SpotBugs priority: 1=High, 2=Medium, else=Low
#         p = str(b.get("@priority") or b.get("priority") or "3")
#         if p == "1":
#             sev["HIGH"] += 1
#         elif p == "2":
#             sev["MEDIUM"] += 1
#         else:
#             sev["LOW"] += 1
#     return sum(sev.values()), sev

# def count_gitleaks(d: Dict) -> Tuple[int, Dict[str, int]]:
#     findings = d.get("findings") or d.get("leaks") or []
#     total = len(findings) if isinstance(findings, list) else 0
#     # Many outputs lack per-finding severity → count all as HIGH for visibility
#     sev = {"CRITICAL": 0, "HIGH": total, "MEDIUM": 0, "LOW": 0}
#     return total, sev

# def count_trivy(d: Dict) -> Tuple[int, Dict[str, int]]:
#     sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
#     total = 0
#     for r in d.get("Results", []) or []:
#         for v in r.get("Vulnerabilities") or []:
#             total += 1
#             s = (v.get("Severity") or "").upper()
#             if s in sev:
#                 sev[s] += 1
#     return total, sev

# def count_checkov(d: Dict) -> Tuple[int, Dict[str, int]]:
#     sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
#     res = d.get("results", {}) or {}
#     failed = res.get("failed_checks") or []
#     for f in failed:
#         s = (f.get("severity") or "").upper()
#         if s in sev:
#             sev[s] += 1
#     return len(failed), sev

# def count_zap(d: Dict) -> Tuple[int, Dict[str, int]]:
#     sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
#     total = 0
#     for site in d.get("site", []) or []:
#         for a in site.get("alerts") or []:
#             total += 1
#             risk = str(a.get("riskcode", "0"))
#             # ZAP: 0=info, 1=low, 2=medium, 3=high
#             if risk == "3":
#                 sev["HIGH"] += 1
#             elif risk == "2":
#                 sev["MEDIUM"] += 1
#             elif risk == "1":
#                 sev["LOW"] += 1
#             else:
#                 sev["LOW"] += 1  # treat info as low in this table
#     return total, sev

# # ---------- Router by filename ----------

# def route(filename: str, data: Dict) -> Tuple[int, Dict[str, int]]:
#     fn = filename.lower()
#     if "semgrep" in fn:
#         return count_semgrep(data)
#     if "spotbugs" in fn:
#         return count_spotbugs(data)
#     if "gitleaks" in fn:
#         return count_gitleaks(data)
#     if "trivy" in fn and "fs" in fn:
#         return count_trivy(data)
#     if "trivy" in fn and "image" in fn:
#         return count_trivy(data)
#     if "checkov" in fn:
#         return count_checkov(data)
#     if "zap" in fn:
#         return count_zap(data)
#     # Unknown file → zeros
#     return 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

# # ---------- Main ----------

# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("--stage", required=True)
#     ap.add_argument("--reports", required=True)
#     ap.add_argument("--files", required=True, help="Comma-separated list of filenames to parse")
#     args = ap.parse_args()

#     reports_dir = pathlib.Path(args.reports).resolve()
#     files = [f.strip() for f in args.files.split(",") if f.strip()]

#     rows = []
#     generated = []
#     for fn in files:
#         p = reports_dir / fn
#         if p.exists() and p.stat().st_size > 0:
#             d = load_json(p)
#             t, sev = route(fn, d)
#             rows.append((fn, t, sev))
#             generated.append(fn)
#         else:
#             rows.append((fn, 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}))

#     md = []
#     md.append(f"### {args.stage} — Reports & Severity")
#     md.append("")
#     md.append("| Report file | Total | Critical | High | Medium | Low |")
#     md.append("|-------------|------:|--------:|-----:|------:|----:|")
#     for fn, total, sev in rows:
#         md.append(f"| `{fn}` | {total} | {sev['CRITICAL']} | {sev['HIGH']} | {sev['MEDIUM']} | {sev['LOW']} |")

#     md.append("\n**Files generated:**")
#     if generated:
#         for g in generated:
#             md.append(f"- {g}")
#     else:
#         md.append("- (none)")

#     summary_path = reports_dir / f"{args.stage}-summary.md"
#     summary_path.write_text("\n".join(md), encoding="utf-8")

#     print("\n".join(md))

#     # Expose output path to the composite action wrapper
#     gout = os.environ.get("GITHUB_OUTPUT")
#     if gout:
#         with open(gout, "a", encoding="utf-8") as f:
#             f.write(f"summary_path={summary_path}\n")

# if __name__ == "__main__":
#     main()