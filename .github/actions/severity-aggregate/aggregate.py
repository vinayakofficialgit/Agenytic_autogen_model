#!/usr/bin/env python3
import argparse
import json
import os
import glob
import pathlib

BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ORDER   = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

def norm_sev(s: str) -> str:
    s = (s or "").upper()
    if s in BUCKETS: 
        return s
    # Common mappings
    if s in ("ERROR", "SEVERE"):
        return "HIGH"
    if s in ("WARN", "WARNING"):
        return "MEDIUM"
    if s in ("INFO", "INFORMATIONAL", "INFORMATION"):
        return "LOW"
    # ZAP risk codes (0=info, 1=low, 2=medium, 3=high)
    if s in ("3", "2", "1", "0"):
        return {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}[s]
    return "LOW"

def load_json(p: pathlib.Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, help="Directory with scanner JSONs")
    ap.add_argument("--out",     required=True, help="Output directory")
    ap.add_argument("--min-severity", required=True, help="CRITICAL|HIGH|MEDIUM|LOW")
    args = ap.parse_args()

    in_dir  = pathlib.Path(args.reports).resolve()
    out_dir = pathlib.Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(glob.glob(str(in_dir / "*.json")))

    tally   = {b: 0 for b in BUCKETS}
    seen    = set()
    details = []

    def add_one(sev, key, tool, meta):
        if key in seen:
            return
        seen.add(key)
        sev = norm_sev(sev)
        tally[sev] += 1
        if len(details) < 50:
            details.append({"tool": tool, "severity": sev, "key": key, "meta": meta})

    # ---- Parsers per tool ----------------------------------------------------

    def semgrep(data, fn):
        for r in data.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            sev   = extra.get("severity")
            path  = (r.get("path") or extra.get("metadata", {}).get("file", "")) or ""
            start = (((r.get("start") or {}).get("line"))
                     or ((r.get("start", {}).get("location") or {}).get("line"))) or 0
            rule  = extra.get("engine_rule_id") or extra.get("rule_id") or "rule"
            key   = f"semgrep:{rule}:{path}:{start}"
            add_one(sev, key, "semgrep", {"path": path, "rule": rule, "start": start})

    def spotbugs(data, fn):
        coll = data.get("BugCollection", {}) or {}
        bugs = coll.get("BugInstance", []) or []
        if isinstance(bugs, dict):
            bugs = [bugs]
        for b in bugs:
            prio = str(b.get("@priority") or b.get("priority") or "3")
            sev  = {"1": "HIGH", "2": "MEDIUM"}.get(prio, "LOW")
            btype= b.get("@type") or b.get("type") or "bug"
            cls, line = "", ""

            c = b.get("Class") or {}
            if isinstance(c, list):
                cls = (c[0].get("@classname") if c and isinstance(c[0], dict) else "") or ""
            elif isinstance(c, dict):
                cls = c.get("@classname") or c.get("classname") or ""

            loc = b.get("SourceLine") or {}
            if isinstance(loc, list):
                line = (loc[0].get("@start") if loc and isinstance(loc[0], dict) else "") or ""
            elif isinstance(loc, dict):
                line = loc.get("@start") or loc.get("start") or ""

            key = f"spotbugs:{btype}:{cls}:{line}"
            add_one(sev, key, "spotbugs", {"type": btype, "class": cls, "line": line})

    def checkov(data, fn):
        for fnd in (data.get("results", {}) or {}).get("failed_checks", []) or []:
            sev   = fnd.get("severity")
            cid   = fnd.get("check_id") or "CHK"
            fpath = fnd.get("file_path") or ""
            res   = fnd.get("resource") or fnd.get("bc_id") or ""
            key   = f"checkov:{cid}:{fpath}:{res}"
            add_one(sev, key, "checkov", {"check_id": cid, "file": fpath, "resource": res})

    def trivy(data, fn):
        for r in data.get("Results", []) or []:
            target = r.get("Target") or ""
            for v in r.get("Vulnerabilities") or []:
                sev = v.get("Severity")
                vid = v.get("VulnerabilityID") or ""
                pkg = v.get("PkgName") or ""
                ver = v.get("InstalledVersion") or ""
                key = f"{'trivyimg' if 'image' in fn else 'trivyfs'}:{vid}:{pkg}:{ver}:{target}"
                add_one(sev, key, "trivy", {"id": vid, "pkg": pkg, "ver": ver, "target": target})

    def zap(data, fn):
        for site in data.get("site", []) or []:
            for a in site.get("alerts") or []:
                rc   = str(a.get("riskcode", "0"))
                sev  = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "LOW"}.get(rc, "LOW")
                name = a.get("alert") or ""
                url  = a.get("url") or ""
                par  = a.get("param") or ""
                key  = f"zap:{name}:{url}:{par}"
                add_one(sev, key, "zap", {"alert": name, "url": url, "param": par})

    def gitleaks(data, fn):
        if isinstance(data, list):
            arr = data
        elif isinstance(data, dict):
            arr = data.get("findings") or data.get("leaks") or []
            if not isinstance(arr, list):
                arr = []
        else:
            arr = []

        for fnd in arr:
            fp   = (fnd.get("Fingerprint") or fnd.get("fingerprint") or "")
            rule = (fnd.get("RuleID") or fnd.get("rule") or fnd.get("rule_id") or "GL")
            file = (fnd.get("File") or fnd.get("file") or "")
            line = str(fnd.get("Line") or fnd.get("line") or "")
            sev  = "HIGH"  # default for gitleaks (schema often lacks severities)
            key  = f"gitleaks:{fp or (file + ':' + line + ':' + rule)}"
            add_one(sev, key, "gitleaks", {"file": file, "line": line, "rule": rule})

    routers = [
        ("semgrep",  semgrep),
        ("spotbugs", spotbugs),
        ("checkov_", checkov),
        ("trivy",    trivy),
        ("zap",      zap),
        ("gitleaks", gitleaks),
    ]

    # ---- Route by filename and aggregate ------------------------------------
    for fp in files:
        data = load_json(pathlib.Path(fp))
        fn   = pathlib.Path(fp).name.lower()
        for name, handler in routers:
            if name in fn:
                if isinstance(data, (dict, list)):
                    handler(data, fn)
                break

    # ---- Decision -----------------------------------------------------------
    min_sev = (args.min_severity or "HIGH").upper()
    thr = ORDER.get(min_sev, 2)
    fail = any(v > 0 for s, v in tally.items() if ORDER[s] >= thr)
    decision = "FAIL" if fail else "PASS"

    summary = {
        "min_severity": min_sev,
        "decision": decision,
        "totals": tally,
        "unique_findings": len(seen),
        "inputs": [pathlib.Path(f).name for f in files],
    }

    # JSON summary
    (out_dir / "overall_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    # Markdown summary
    md = []
    md.append(f"### Overall Severity (deduped across tools)\n**Threshold:** `{min_sev}` → **Decision:** `{decision}`\n")
    md.append("| Severity | Count |")
    md.append("|----------|------:|")
    for s in BUCKETS:
        md.append(f"| {s} | {tally[s]} |")
    md.append(f"\n**Unique findings:** {len(seen)}")
    md.append("\n\n**Files considered:**")
    for n in summary["inputs"]:
        md.append(f"- {n}")
    (out_dir / "overall_summary.md").write_text("\n".join(md), encoding="utf-8")

    # Output variables for the composite action
    gout = os.environ.get("GITHUB_OUTPUT")
    if gout:
        with open(gout, "a", encoding="utf-8") as f:
            f.write(f"decision={decision}\n")
            f.write(f"critical={tally['CRITICAL']}\n")
            f.write(f"high={tally['HIGH']}\n")
            f.write(f"medium={tally['MEDIUM']}\n")
            f.write(f"low={tally['LOW']}\n")

if __name__ == "__main__":
    main()