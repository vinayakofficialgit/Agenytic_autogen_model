



# main.py
"""
DevSecOps Agentic AI Pipeline - Dynamic Output-Specific Suggestions

Key Features:
- Dynamic suggestions based on ACTUAL scan findings
- No generic/static best practices
- Concise, actionable remediation specific to each finding
- File locations and exact fixes
"""

import argparse
import os
import json
import sys
from pathlib import Path
from datetime import datetime
from io import StringIO
import contextlib

try:
    import yaml
except Exception:
    yaml = None


def load_env_from_file(env_file: str = ".env", override: bool = False) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ."""
    p = Path(env_file)
    if not p.exists():
        return
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if override or key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


@contextlib.contextmanager
def suppress_verbose_output():
    """Suppress stdout during LLM calls to keep output clean."""
    if os.getenv("LLM_VERBOSE", "0") == "1":
        yield
    else:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            yield
        finally:
            sys.stdout = old_stdout


# LLM imports
try:
    from agents.llm_bridge import assistant_factory, check_ollama_health, get_fallback_suggestion
except Exception:
    try:
        from llm_bridge import assistant_factory, check_ollama_health, get_fallback_suggestion
    except Exception:
        assistant_factory = None
        check_ollama_health = None
        get_fallback_suggestion = None


# Core agent imports
try:
    from agents.collector import CollectorAgent
    from agents.policy_gate import PolicyGate
    from agents.reporter import Reporter
    from agents.fixer import Fixer
    from agents.autogen_runtime import run_autogen_layer
except Exception:
    from collector import CollectorAgent
    from policy_gate import PolicyGate
    from reporter import Reporter
    from fixer import Fixer
    from autogen_runtime import run_autogen_layer


def _load_cfg() -> dict:
    """Load config from settings.yaml or use defaults."""
    default_cfg = {
        "inputs": {"reports_dir": "reports", "output_dir": "agent_output"},
        "policy": {
            "remediation": {"auto_pr": True},
            "min_severity_to_fail": os.getenv("MIN_SEVERITY", "critical"),
        },
        "llm": {
            "enabled": bool(os.getenv("OLLAMA_URL")) or (os.getenv("LLM_ENABLED", "").strip() == "1"),
            "model": os.getenv("OLLAMA_MODEL", "llama3:latest"),
            "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
        },
        "tool_alias": {
            "owasp-dep-check": "dependency-check",
            "dependency-check": "dependency-check",
            "spotbugs": "spotbugs",
            "zap": "zap",
            "trivy-image": "trivy_image"
        },        
        "remediation": {
            "defaults": {
                "docker_nonroot_user": "appuser",
                "k8s_default_cpu_limit": "250m",
                "k8s_default_mem_limit": "256Mi",
                "terraform_allowed_cidr": "10.0.0.0/24",
            }
        },
        "dedup_keys": ["tool", "id", "location"],
        "normalize_severity": True,
        "write_output": True,
    }

    cfg_path = Path("config/settings.yaml")
    if yaml and cfg_path.exists():
        try:
            with cfg_path.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            for k, v in loaded.items():
                if isinstance(v, dict) and isinstance(default_cfg.get(k), dict):
                    default_cfg[k].update(v)
                else:
                    default_cfg[k] = v
        except Exception:
            pass
    
    return default_cfg


def print_banner():
    """Print startup banner."""
    print("\n" + "=" * 70)
    # print("   🛡️  DevSecOps Agentic AI Security Scanner")
    print("   ☕ Multi-language Security Orchestrator (Java Enabled)")
    print("=" * 70)
    print(f"   📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   🤖 LLM: {os.getenv('OLLAMA_MODEL', 'llama3:latest')} @ {os.getenv('OLLAMA_URL', 'localhost:11434')}")
    print("=" * 70 + "\n")


def print_phase1_results(findings_grouped: dict, decision: dict):
    """PHASE 1: Print clean scan results and decision."""
    print("\n" + "━" * 70)
    print("   📊  SCAN RESULTS")
    print("━" * 70)
    
    stats = decision.get("stats", {})
    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})
    
    print(f"\n   Total Findings: {total}")
    print(f"   ┌{'─'*50}┐")
    print(f"   │ 🔴 Critical: {by_sev.get('critical', 0):3d}  │  🟠 High: {by_sev.get('high', 0):3d}           │")
    print(f"   │ 🟡 Medium:   {by_sev.get('medium', 0):3d}  │  🟢 Low:  {by_sev.get('low', 0):3d}            │")
    print(f"   └{'─'*50}┘")
    
    # By tool
    by_tool = stats.get("by_tool", {})
    if by_tool:
        print(f"\n   By Tool:")
        for tool, count in sorted(by_tool.items(), key=lambda x: -x[1]):
            print(f"      • {tool}: {count}")
    
    # Violations
    violations = decision.get("violations", [])
    if violations:
        print(f"\n   ⚠️  Issues Found ({len(violations)}):")
        for i, v in enumerate(violations[:5], 1):
            sev = v.get("severity", "").upper()
            sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
            print(f"   {i}. {sev_icon} [{sev}] {v.get('tool', '')} @ {v.get('location', '')}")
    
    # Decision
    status = decision.get("status", "ok")
    print(f"\n   {'─'*50}")
    if status == "fail":
        print(f"   ❌ DECISION: FAIL - {decision.get('reason', '')}")
    else:
        print(f"   ✅ DECISION: PASS")
    print("━" * 70)


def generate_dynamic_suggestion(item: dict, tool: str) -> dict:
    """
    Generate DYNAMIC, context-specific suggestion based on actual finding.
    Returns dict with: issue, location, quick_fix, command (if applicable)
    """
    suggestion = {
        "issue": "",
        "location": "",
        "quick_fix": "",
        "command": None,
        "severity": item.get("severity", "medium").upper()
    }
    
    if tool == "semgrep":
        file_path = item.get("file", "unknown")
        line = item.get("line", "?")
        rule_id = item.get("rule_id", "")
        message = item.get("message", "")
        
        suggestion["location"] = f"{file_path}:{line}"
        suggestion["issue"] = message or f"Security issue detected by rule {rule_id}"
        
        # Generate specific fix based on rule
        rule_lower = rule_id.lower()
        if "password" in rule_lower or "hardcoded" in rule_lower:
            suggestion["quick_fix"] = f"""
   → Open {file_path} at line {line}
   → Replace hardcoded value with: os.environ.get('SECRET_NAME')
   → Add SECRET_NAME to your .env file"""
        elif "sql" in rule_lower or "injection" in rule_lower:
            suggestion["quick_fix"] = f"""
   → Open {file_path} at line {line}
   → Use parameterized query: cursor.execute(query, (param,))"""
        elif "subprocess" in rule_lower or "shell" in rule_lower:
            suggestion["quick_fix"] = f"""
   → Open {file_path} at line {line}
   → Set shell=False and pass args as list: subprocess.run(['cmd', 'arg1'])"""
        else:
            suggestion["quick_fix"] = f"""
   → Open {file_path} at line {line}
   → Review and fix the security issue"""
    
    elif tool in ("trivy_fs", "trivy-fs"):
        file_path = item.get("file", "unknown")
        vuln_id = item.get("id", "")
        summary = item.get("summary", "")
        
        suggestion["location"] = file_path
        suggestion["issue"] = summary or f"Vulnerability {vuln_id}"
        
        if "CVE" in vuln_id:
            suggestion["quick_fix"] = f"""
   → Update the vulnerable package/image
   → Check if patch is available for {vuln_id}"""
            suggestion["command"] = "pip install --upgrade <package>  # or update base image"
        elif "root" in summary.lower() or "user" in summary.lower():
            suggestion["quick_fix"] = f"""
   → Add to {file_path}:
     RUN adduser --disabled-password appuser
     USER appuser"""
        elif "add" in summary.lower():
            suggestion["quick_fix"] = f"""
   → In {file_path}: Replace ADD with COPY"""
        else:
            suggestion["quick_fix"] = f"""
   → Review {file_path} for the misconfiguration"""
    
    elif tool == "gitleaks":
        file_path = item.get("file", "unknown")
        line = item.get("line", "?")
        rule_id = item.get("rule_id", "")
        
        suggestion["location"] = f"{file_path}:{line}"
        suggestion["issue"] = f"Exposed secret: {rule_id}"
        suggestion["quick_fix"] = f"""
   → IMMEDIATELY rotate/revoke this credential!
   → Remove from {file_path}
   → Use environment variable instead"""
        suggestion["command"] = f"# Remove secret from git history:\ngit filter-branch --force --index-filter 'git rm --cached --ignore-unmatch {file_path}'"
    
    elif tool == "tfsec":
        location = item.get("location", item.get("file", "unknown"))
        rule_id = item.get("rule_id", item.get("id", ""))
        description = item.get("description", item.get("message", ""))
        
        suggestion["location"] = location
        suggestion["issue"] = description
        
        if "0.0.0.0" in description or "cidr" in description.lower():
            suggestion["quick_fix"] = f"""
   → In {location}: Change cidr_blocks = ["0.0.0.0/0"]
   → To: cidr_blocks = ["10.0.0.0/8"] or your VPC CIDR"""
        elif "encrypt" in description.lower():
            suggestion["quick_fix"] = f"""
   → Enable encryption in {location}"""
        else:
            suggestion["quick_fix"] = f"""
   → Fix the issue in {location}"""
    
    elif tool == "spotbugs":
        file_path = item.get("file", "unknown")
        bug = item.get("bug_type", item.get("id", ""))
        message = item.get("message", "")

        suggestion["location"] = file_path
        suggestion["issue"] = message or f"SpotBugs issue {bug}"

        if "SQL" in bug.upper():
            suggestion["quick_fix"] = """
   → Replace concatenated SQL with PreparedStatement
   → Use parameterized queries"""
        elif "XSS" in bug.upper():
            suggestion["quick_fix"] = """
   → Encode user input before rendering
   → Use Spring Security encoder"""
        else:
            suggestion["quick_fix"] = f"""
   → Fix issue in {file_path}"""

    elif tool == "dependency-check":
        pkg = item.get("package", item.get("file", ""))
        cve = item.get("id", "")
        suggestion["location"] = pkg
        suggestion["issue"] = f"Vulnerable dependency {pkg} ({cve})"
        suggestion["quick_fix"] = """
   → Update dependency version in pom.xml
   → mvn versions:use-latest-releases"""

    elif tool == "zap":
        url = item.get("url", "")
        alert = item.get("alert", item.get("message", ""))
        suggestion["location"] = url
        suggestion["issue"] = alert
        suggestion["quick_fix"] = f"""
   → Fix vulnerability on endpoint {url}
   → Add validation/authentication/headers"""

    elif tool == "conftest":
        file_path = item.get("file", "unknown")
        msg = item.get("message", "")
        suggestion["location"] = file_path
        suggestion["issue"] = msg
        suggestion["quick_fix"] = """
   → Update config to satisfy policy
   → Review OPA rule violation"""

    elif tool == "trivy_image":
        image = item.get("image", "")
        cve = item.get("id", "")
        suggestion["location"] = image
        suggestion["issue"] = f"Container vulnerability {cve}"
        suggestion["quick_fix"] = """
   → Update base image
   → Rebuild container with patched version"""    
    
    return suggestion


def print_phase2_dynamic_suggestions(llm_report: dict, findings_grouped: dict, decision: dict):
    """
    PHASE 2: Print DYNAMIC suggestions based on actual scan output.
    No generic advice - everything is specific to the findings.
    """
    print("\n" + "━" * 70)
    print("   🔧  REMEDIATION (Specific to Your Findings)")
    print("━" * 70)
    
    if not llm_report and not findings_grouped:
        print("\n   ✅ No issues to remediate!")
        print("━" * 70)
        return
    
    # Check if LLM was used or fallback
    total_findings = 0
    llm_used = False
    
    # Process Semgrep findings
    # semgrep_items = llm_report.get("semgrep", []) if llm_report else []
    
    if isinstance(llm_report, dict):
        semgrep_items = llm_report.get("semgrep", [])
    else:
        semgrep_items = []

    if not semgrep_items:
        semgrep_items = findings_grouped.get("semgrep", []) if findings_grouped else []
    
    if semgrep_items:
        print(f"\n   📝 CODE ISSUES ({len(semgrep_items)} found)")
        print("   " + "─" * 50)
        
        for i, item in enumerate(semgrep_items, 1):
            total_findings += 1
            sev = (item.get("severity") or "medium").upper()
            sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
            
            # Check if LLM provided suggestion
            suggestion_text = item.get("suggestion", "")
            used_fallback = item.get("used_fallback", True)
            
            if suggestion_text and "[Fallback" not in suggestion_text and not used_fallback:
                llm_used = True
                # LLM-generated suggestion - print it directly
                print(f"\n   {i}. {sev_icon} [{sev}] {item.get('file', '')}:{item.get('line', '')}")
                print(f"      Rule: {item.get('rule_id', '')}")
                print("")
                # Clean and print LLM suggestion
                clean_suggestion = suggestion_text.replace("[Fallback - LLM unavailable]", "").strip()
                for line in clean_suggestion.split("\n")[:10]:  # Limit lines
                    print(f"      {line}")
            else:
                # Generate dynamic suggestion
                sugg = generate_dynamic_suggestion(item, "semgrep")
                print(f"\n   {i}. {sev_icon} [{sev}] {sugg['location']}")
                print(f"      Issue: {sugg['issue'][:60]}...")
                print(f"      Fix:{sugg['quick_fix']}")
    
    # Process Trivy findings
    trivy_items = llm_report.get("trivy_fs", []) if isinstance(llm_report, dict) else []
    if not trivy_items:
        trivy_items = findings_grouped.get("trivy_fs", []) if findings_grouped else []
    
    if trivy_items:
        print(f"\n   🐳 INFRASTRUCTURE ISSUES ({len(trivy_items)} found)")
        print("   " + "─" * 50)
        
        for i, item in enumerate(trivy_items, 1):
            total_findings += 1
            sev = (item.get("severity") or "medium").upper()
            sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
            
            suggestion_text = item.get("suggestion", "")
            used_fallback = item.get("used_fallback", True)
            
            if suggestion_text and "[Fallback" not in suggestion_text and not used_fallback:
                llm_used = True
                print(f"\n   {i}. {sev_icon} [{sev}] {item.get('file', '')} ({item.get('id', '')})")
                clean_suggestion = suggestion_text.replace("[Fallback - LLM unavailable]", "").strip()
                for line in clean_suggestion.split("\n")[:8]:
                    print(f"      {line}")
            else:
                sugg = generate_dynamic_suggestion(item, "trivy_fs")
                print(f"\n   {i}. {sev_icon} [{sev}] {sugg['location']} ({item.get('id', '')})")
                print(f"      Issue: {sugg['issue'][:60]}...")
                print(f"      Fix:{sugg['quick_fix']}")
                if sugg.get("command"):
                    print(f"      Command: {sugg['command']}")

    # Process spotbug findings                
    spotbugs_items = findings_grouped.get("spotbugs", []) if findings_grouped else []
    if spotbugs_items:
        print(f"\n   ☕ JAVA CODE ISSUES ({len(spotbugs_items)} found)")
        print("   " + "─" * 50)
        for i, item in enumerate(spotbugs_items, 1):
            sugg = generate_dynamic_suggestion(item, "spotbugs")
            print(f"\n   {i}. {sugg['location']}")
            print(f"      Issue: {sugg['issue'][:60]}...")
            print(f"      Fix:{sugg['quick_fix']}")
   
    # Dependency check findings
    dep_items = findings_grouped.get("dependency-check", []) if findings_grouped else []
    if dep_items:
        print(f"\n   📦 DEPENDENCY VULNS ({len(dep_items)} found)")
        print("   " + "─" * 50)
        for i, item in enumerate(dep_items, 1):
            sugg = generate_dynamic_suggestion(item, "dependency-check")
            print(f"\n   {i}. {sugg['location']}")
            print(f"      Issue: {sugg['issue']}")
            print(f"      Fix:{sugg['quick_fix']}")

    # ZAP check findings
    zap_items = findings_grouped.get("zap", []) if findings_grouped else []
    if zap_items:
        print(f"\n   🌐 DAST ISSUES ({len(zap_items)} found)")
        print("   " + "─" * 50)
        for i, item in enumerate(zap_items, 1):
            sugg = generate_dynamic_suggestion(item, "zap")
            print(f"\n   {i}. {sugg['location']}")
            print(f"      Issue: {sugg['issue']}")
            print(f"      Fix:{sugg['quick_fix']}") 

    # Process Gitleaks findings
    gitleaks_items = findings_grouped.get("gitleaks", []) if findings_grouped else []
    if gitleaks_items:
        print(f"\n   🔑 EXPOSED SECRETS ({len(gitleaks_items)} found) ⚠️ URGENT!")
        print("   " + "─" * 50)
        
        for i, item in enumerate(gitleaks_items[:3], 1):  # Limit to 3
            total_findings += 1
            sugg = generate_dynamic_suggestion(item, "gitleaks")
            print(f"\n   {i}. 🔴 [CRITICAL] {sugg['location']}")
            print(f"      Secret Type: {item.get('rule_id', 'unknown')}")
            print(f"      ⚠️ ROTATE THIS CREDENTIAL IMMEDIATELY!")
            print(f"      Fix:{sugg['quick_fix']}")
    
    # Process tfsec findings
    tfsec_items = findings_grouped.get("tfsec", []) if findings_grouped else []
    if tfsec_items:
        print(f"\n   ☁️ TERRAFORM ISSUES ({len(tfsec_items)} found)")
        print("   " + "─" * 50)
        
        for i, item in enumerate(tfsec_items[:3], 1):
            total_findings += 1
            sugg = generate_dynamic_suggestion(item, "tfsec")
            sev = (item.get("severity") or "medium").upper()
            sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
            print(f"\n   {i}. {sev_icon} [{sev}] {sugg['location']}")
            print(f"      Issue: {sugg['issue'][:60]}...")
            print(f"      Fix:{sugg['quick_fix']}")
    
    # Summary
    print(f"\n   " + "─" * 50)
    if llm_used:
        print(f"   ✨ AI-powered suggestions provided")
    else:
        print(f"   📋 Context-specific suggestions provided (LLM unavailable)")
    print(f"   📊 Total issues to fix: {total_findings}")
    
    # Priority action
    stats = decision.get("stats", {})
    by_sev = stats.get("by_severity", {})
    critical = by_sev.get("critical", 0)
    high = by_sev.get("high", 0)
    
    if critical > 0:
        print(f"\n   🚨 PRIORITY: Fix {critical} CRITICAL issue(s) before deployment!")
    elif high > 0:
        print(f"\n   ⚠️ PRIORITY: Fix {high} HIGH severity issue(s)")
    
    print("━" * 70)


def print_quick_actions(decision: dict, findings_grouped: dict):
    """Print quick action commands based on actual findings."""
    print("\n" + "━" * 70)
    print("   ⚡ QUICK ACTIONS")
    print("━" * 70)
    
    actions = []
    
    # Check what tools found issues
    stats = decision.get("stats", {})
    by_tool = stats.get("by_tool", {})
    
    if by_tool.get("semgrep", 0) > 0:
        actions.append("   # Re-run Semgrep after fixes:")
        actions.append("   semgrep scan --config=auto .")

    if by_tool.get("dependency-check", 0) > 0:
        actions.append("\n   # Update Maven dependencies:")
        actions.append("   mvn versions:display-dependency-updates")
        actions.append("   mvn versions:use-latest-releases")
    
    if by_tool.get("spotbugs", 0) > 0:
        actions.append("\n   # Re-run SpotBugs:")
        actions.append("   mvn spotbugs:spotbugs")
    
    if by_tool.get("zap", 0) > 0:
        actions.append("\n   # Re-run ZAP:")
        actions.append("   zap-baseline.py -t http://localhost:8080")  

    if by_tool.get("gitleaks", 0) > 0:
        actions.append("\n   # Check for secrets:")
        actions.append("   gitleaks detect --source . --verbose")

    if by_tool.get("tfsec", 0) > 0:
        actions.append("\n   # Re-run Terraform scan:")
        actions.append("   tfsec terraform/")              
    
    # if by_tool.get("trivy_fs", 0) > 0 or by_tool.get("trivy-fs", 0) > 0:
    #     actions.append("\n   # Update dependencies:")
    #     actions.append("   pip install --upgrade -r requirements.txt")
    #     actions.append("   # Or rebuild Docker image:")
    #     actions.append("   docker build --no-cache -t myapp .")
    
    # if by_tool.get("gitleaks", 0) > 0:
    #     actions.append("\n   # Check for secrets:")
    #     actions.append("   gitleaks detect --source . --verbose")
    
    # if by_tool.get("tfsec", 0) > 0:
    #     actions.append("\n   # Re-run Terraform scan:")
    #     actions.append("   tfsec terraform/")
    
    if actions:
        for action in actions:
            print(action)
    else:
        print("   ✅ No immediate actions required")
    
    print("\n   # Re-run this pipeline after fixes:")
    print("   python main.py")
    print("━" * 70)


def print_final_summary(decision: dict, output_dir: Path):
    """Print final summary with output file locations."""
    print("\n" + "=" * 70)
    print("   📁  OUTPUT FILES")
    print("=" * 70)
    
    files = [
        ("decision.json", "Full report"),
        ("llm_report.json", "AI analysis"),
        ("llm_recommendations.md", "Detailed fixes"),
        ("pr_comment.md", "PR comment"),
    ]
    
    for fname, desc in files:
        fpath = output_dir / fname
        if fpath.exists():
            print(f"   ✓ {fname:25s} - {desc}")
    
    status = decision.get("status", "ok")
    print("\n" + "=" * 70)
    if status == "fail":
        print("   ❌  STATUS: FAILED - Fix issues and re-run")
    else:
        print("   ✅  STATUS: PASSED")
    print("=" * 70 + "\n")


def main():
    """Main entry point."""
    load_env_from_file(".env", override=False)

    parser = argparse.ArgumentParser(description="DevSecOps Agentic AI Pipeline")
    parser.add_argument("--mode", default=os.getenv("MODE", "real"), choices=["mock", "real"])
    parser.add_argument("--outputs-env", default=os.getenv("GITHUB_OUTPUT"))
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--skip-llm", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        os.environ["LLM_VERBOSE"] = "1"

    print_banner()

    cfg = _load_cfg()
    reports_dir = Path(cfg["inputs"]["reports_dir"])
    output_dir = Path(cfg["inputs"]["output_dir"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1) Collect findings
    print("   ⏳ Scanning...")
    findings_grouped = {}
    try:
        with suppress_verbose_output():
            collector = CollectorAgent(cfg, reports_dir, output_dir)
            findings_grouped = collector.load_all()
    except Exception as e:
        print(f"   ❌ Error: {e}")
        findings_grouped = {}

    try:
        (output_dir / "merged_findings.json").write_text(
            json.dumps({"findings": findings_grouped}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    # 2) Policy Gate
    print("   ⏳ Evaluating policy...")
    decision = {}
    try:
        with suppress_verbose_output():
            decision = PolicyGate(cfg, output_dir).decide(findings_grouped)
    except Exception as e:
        decision = {"status": "ok", "reason": f"Error: {e}"}

    if "open_pr" not in decision:
        decision["open_pr"] = bool(decision.get("status") == "fail")

    # 3) LLM Analysis
    llm_report = None
    if not args.skip_llm:
        print("   ⏳ Analyzing...")
        try:
            with suppress_verbose_output():
                llm_report = run_autogen_layer(findings_grouped, cfg, output_dir)
            if llm_report:
                decision.setdefault("remediation", {})
                decision["remediation"]["llm_report"] = llm_report
                decision["remediation"]["llm_report_path"] = str(output_dir / "llm_report.json")
        except Exception:
            pass

    # 4) Auto-remediation
    try:
        if decision.get("status") == "fail" and cfg.get("policy", {}).get("remediation", {}).get("auto_pr", True):
            with suppress_verbose_output():
                fix_info = Fixer(cfg, output_dir).apply(findings_grouped)
                decision.setdefault("remediation", {})
                if isinstance(fix_info, dict):
                    for k, v in fix_info.items():
                        if k != "llm_report" and (v is not None or k not in decision["remediation"]):
                            decision["remediation"][k] = v
    except Exception:
        pass

    # 5) Reporting
    try:
        with suppress_verbose_output():
            Reporter(cfg, output_dir).emit(findings_grouped, decision)
    except Exception:
        pass

    # 6) Write decision
    try:
        with (output_dir / "decision.json").open("w", encoding="utf-8") as f:
            json.dump(decision, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    # GitHub output
    if args.outputs_env:
        try:
            with open(args.outputs_env, "a", encoding="utf-8") as f:
                f.write(f"pipeline_status={decision.get('status','ok')}\n")
                f.write(f"open_pr={'true' if decision.get('open_pr') else 'false'}\n")
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    # DYNAMIC OUTPUT - Based on actual findings
    # ═══════════════════════════════════════════════════════════════
    
    # Phase 1: Scan Results
    print_phase1_results(findings_grouped, decision)
    
    # Phase 2: Dynamic Suggestions (specific to findings)
    print_phase2_dynamic_suggestions(llm_report, findings_grouped, decision)
    
    # Phase 3: Quick Actions (based on what was found)
    print_quick_actions(decision, findings_grouped)
    
    # Final Summary
    print_final_summary(decision, output_dir)

    return 1 if decision.get("status") == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
