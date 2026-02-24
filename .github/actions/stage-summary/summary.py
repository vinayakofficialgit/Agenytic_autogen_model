#!/usr/bin/env python3
import argparse, json, pathlib, sys

def load_json(path: pathlib.Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}

def count_semgrep(d):
    results = d.get("results", []) or []
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for r in results:
        s = ((r.get("extra") or {}).get("severity") or "").upper()
        # Map common Semgrep severities to our buckets
        if s == "ERROR": s = "HIGH"
        elif s == "WARNING": s = "MEDIUM"
        elif s == "INFO": s = "LOW"
        if s in sev: sev[s]+=1
    return sum(sev.values()), sev

def count_spotbugs(d):
    # Expect JSON converted from", "0"))    # Expect JSON converted from XML; if still XML, caller should convert in pipeline
            # ZAP: 0=info, 1=low, 2=medium, 3=high → map info→LOW for our table
            if risk == "3": sev["HIGH"] += 1
            elif risk == "2": sev["MEDIUM"] += 1
            elif risk == "1": sev["LOW"] += 1
            else: sev["LOW"] += 1
    return total, sev

# Heuristic router by filename
def route(filename, data):
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
    # Unknown → 0s
    return 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}

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
            # Still show zero row so table is consistent
            rows.append((fn, 0, {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}))

    md = []
    md.append(f"### {args.stage} — Reports & Severity")
    md.append("")
    md.append("| Report file | Total | Critical | High | Medium | Low |")
    md.append("|-------------|------:|--------:|-----:|------:|----:|")
    for fn, total, sev in rows:
        md.append(f"| `{fn}` | {total} | {sev['CRITICAL']} | {sev['HIGH']} | {sev['MEDIUM']} | {sev['LOW']} |")

    md.append("\n**Files generated:**")
    if generated:
        md.extend([f"- {g}" for g in generated])
    else:
        md.append("- (none)")

    summary_path = reports_dir / f"{args.stage}-summary.md"
    summary_path.write_text("\n".join(md), encoding="utf-8")

    # Expose output to composite action
    print("\n".join(md))
    # Inform the wrapper step about the path via GITHUB_OUTPUT
    gout = pathlib.Path(os.environ.get("GITHUB_OUTPUT", ""))
    if gout:
        gout.write_text(f"summary_path={summary_path}\n", encoding="utf-8")
    else:
        # Fallback: echo the path in a marker the wrapper can ignore
        print(f"::notice::summary_path={summary_path}")

if __name__ == "__main__":
    import os
    main()
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    coll = d.get("BugCollection", {})
    bugs = coll.get("BugInstance", [])
    if isinstance(bugs, dict):
        bugs = [bugs]
    for b in bugs or []:
        # SpotBugs priority: 1=High, 2=Medium, 3/else=Low
        p = str(b.get("@priority") or b.get("priority") or "3")
        if p == "1": sev["HIGH"] += 1
        elif p == "2": sev["MEDIUM"] += 1
        else: sev["LOW"] += 1
    return sum(sev.values()), sev

def count_gitleaks(d):
    findings = d.get("findings") or d.get("leaks") or []
    total = len(findings) if isinstance(findings, list) else 0
    # Gitleaks has no uniform severity in all outputs → count all as HIGH by default
    sev = {"CRITICAL":0,"HIGH":total,"MEDIUM":0,"LOW":0}
    return total, sev

def count_trivy(d):
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    total = 0
    for r in d.get("Results", []) or []:
        vulns = r.get("Vulnerabilities") or []
        total += len(vulns)
        for v in vulns:
            s = (v.get("Severity") or "").upper()
            if s in sev: sev[s] += 1
    return total, sev

def count_checkov(d):
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    res = d.get("results", {}) or {}
    failed = res.get("failed_checks") or []
    for f in failed:
        s = (f.get("severity") or "").upper()
        if s in sev: sev[s] += 1
    return len(failed), sev

def count_zap(d):
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    total = 0
    for site in d.get("site", []) or []:
        for a in site.get("alerts") or []:
            total += 1
