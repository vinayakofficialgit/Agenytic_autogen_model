# main.py
"""
DevSecOps Agentic AI Pipeline

New:
- Writes agent_output/targets.json with canonical affected file paths.
- Fix phase touches ONLY those paths (Fixer allow-list).
- Normalizes decision.status to pass/fail for CI gate.
"""

import argparse
import os
import json
import sys
from pathlib import Path
from datetime import datetime
from io import StringIO
import contextlib
import traceback

try:
    import yaml
except Exception:
    yaml = None

# LLM imports
try:
    from agents.llm_bridge import assistant_factory, check_ollama_health, get_fallback_suggestion
except ImportError:
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).parent / "agents"))
        from llm_bridge import assistant_factory, check_ollama_health, get_fallback_suggestion
    except ImportError:
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


def load_env_from_file(env_file: str = ".env", override: bool = False) -> None:
    p = Path(env_file)
    if not p.exists():
        return
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
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
    # Only suppress during LLM calls; core pipeline should be visible in CI.
    if os.getenv("LLM_VERBOSE", "0") == "1":
        yield
    else:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            yield
        finally:
            sys.stdout = old_stdout


def _load_cfg() -> dict:
    default_cfg = {
        "inputs": {"reports_dir": "reports", "output_dir": "agent_output"},
        "policy": {
            "remediation": {"auto_pr": True},
            "min_severity_to_fail": os.getenv("MIN_SEVERITY", "high"),
        },
        "llm": {
            "enabled": bool(os.getenv("OLLAMA_URL") or os.getenv("OLLAMA_HOST")) or (os.getenv("LLM_ENABLED", "").strip() == "1"),
            "model": os.getenv("LLM_MODEL", "qwen2.5-coder:3b"),
            "temperature": float(os.getenv("OLLAMA_TEMPERATURE", os.getenv("OLLAMA_TEMP", "0.2"))),
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


def _normalize_repo_path(repo_root: Path, p: str) -> str:
    p = (p or "").strip().replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    if not p:
        return ""
    try:
        pp = Path(p)
        if pp.is_absolute():
            rp = str(pp.resolve()).replace("\\", "/")
            rr = str(repo_root.resolve()).replace("\\", "/")
            if rp.startswith(rr + "/"):
                p = rp[len(rr) + 1 :]
            else:
                p = pp.name
    except Exception:
        pass
    return p


def _extract_affected_files(repo_root: Path, findings_grouped: dict) -> dict:
    """
    Builds a strict list of repo-relative files that findings reference.
    Stored as agent_output/targets.json and used as allow-list by Fixer.
    """
    files = set()
    by_tool = {}

    def add(tool: str, path: str):
        rp = _normalize_repo_path(repo_root, path)
        if not rp:
            return
        files.add(rp)
        by_tool.setdefault(tool, set()).add(rp)

    for tool, items in (findings_grouped or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            # Common keys across parsers
            path = (
                it.get("file") or it.get("path") or
                (it.get("location") or {}).get("path") or
                (it.get("artifact") or {}).get("path") or
                ""
            )
            if path:
                add(tool, str(path))

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": sorted(files),
        "by_tool": {k: sorted(v) for k, v in by_tool.items()},
    }


def _normalize_status(decision: dict) -> dict:
    st = (decision.get("status") or "").lower().strip()
    if st in ("ok", "success", "passed", "true", ""):
        decision["status"] = "pass"
    elif st in ("failed", "false"):
        decision["status"] = "fail"
    # keep pass/fail as-is, anything else treat as fail-safe
    elif st not in ("pass", "fail"):
        decision["status"] = "fail"
        decision.setdefault("reason", f"Unknown status '{st}' normalized to fail")
    return decision


def print_banner():
    if not os.getenv("OLLAMA_URL") and os.getenv("OLLAMA_HOST"):
        os.environ["OLLAMA_URL"] = f"http://{os.getenv('OLLAMA_HOST')}"
    print("\n" + "=" * 70)
    print("   🛡️  DevSecOps Agentic AI Security Scanner")
    print("=" * 70)
    print(f"   📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   🤖 LLM: {os.getenv('LLM_MODEL', 'qwen2.5-coder:3b')} @ {os.getenv('OLLAMA_URL', 'localhost:11434')}")
    print("=" * 70 + "\n")


def main():
    load_env_from_file(".env", override=False)

    parser = argparse.ArgumentParser(description="DevSecOps Agentic AI Pipeline")
    parser.add_argument("--mode", default=os.getenv("MODE", "real"), choices=["mock", "real"])
    parser.add_argument("--outputs-env", default=os.getenv("GITHUB_OUTPUT"))
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--skip-llm", action="store_true")

    phase = parser.add_mutually_exclusive_group()
    phase.add_argument("--analysis-only", action="store_true")
    phase.add_argument("--generate-fixes", action="store_true")

    parser.add_argument("--model", default=os.getenv("LLM_MODEL"))
    parser.add_argument("--ollama-url", default=None)

    args = parser.parse_args()
    if args.verbose:
        os.environ["LLM_VERBOSE"] = "1"

    if args.model:
        os.environ["LLM_MODEL"] = args.model
    if args.ollama_url:
        os.environ["OLLAMA_URL"] = args.ollama_url

    print_banner()

    cfg = _load_cfg()
    if args.model:
        cfg.setdefault("llm", {})["model"] = args.model

    repo_root = Path(".")
    reports_dir = Path(cfg["inputs"]["reports_dir"])
    output_dir = Path(cfg["inputs"]["output_dir"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1) Collect findings
    print("   ⏳ Scanning...")
    try:
        collector = CollectorAgent(cfg, reports_dir, output_dir)
        findings_grouped = collector.load_all()
    except Exception as e:
        print(f"   ❌ Collector error: {e}")
        traceback.print_exc()
        findings_grouped = {}

    # Write merged findings
    try:
        (output_dir / "merged_findings.json").write_text(
            json.dumps({"findings": findings_grouped}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass

    # NEW: write targets allow-list
    try:
        targets = _extract_affected_files(repo_root, findings_grouped)
        (output_dir / "targets.json").write_text(json.dumps(targets, indent=2), encoding="utf-8")
        print(f"   ✅ targets.json written with {len(targets.get('files', []))} file(s)")
    except Exception as e:
        print(f"   ⚠️ Could not write targets.json: {e}")

    # 2) Policy Gate
    print("   ⏳ Evaluating policy...")
    try:
        decision = PolicyGate(cfg, output_dir).decide(findings_grouped)
    except Exception as e:
        print(f"[policy] error: {e}")
        traceback.print_exc()
        decision = {"status": "fail", "reason": f"PolicyGate error: {e}"}

    if "open_pr" not in decision:
        decision["open_pr"] = bool((decision.get("status") or "").lower() in ("fail", "failed"))

    # Normalize status to pass/fail for CI gate
    decision = _normalize_status(decision)

    # 3) LLM analysis (optional)
    llm_report = None
    if not args.skip_llm:
        print("   ⏳ Analyzing (LLM layer)...")
        try:
            with suppress_verbose_output():
                llm_report = run_autogen_layer(findings_grouped, cfg, output_dir)
            if llm_report:
                decision.setdefault("remediation", {})
                decision["remediation"]["llm_report"] = llm_report
                decision["remediation"]["llm_report_path"] = str(output_dir / "llm_report.json")
        except Exception as e:
            print(f"[llm] error: {e}")

    # 4) Auto-remediation only when --generate-fixes
    if args.generate_fixes and decision.get("status") == "fail":
        print("[main] Fixer condition met: --generate-fixes and status=fail")
        try:
            fix_info = Fixer(cfg, output_dir, repo_root).apply(findings_grouped)
            decision.setdefault("remediation", {})
            if isinstance(fix_info, dict):
                for k, v in fix_info.items():
                    if k != "llm_report":
                        decision["remediation"][k] = v
        except Exception as e:
            print(f"[main] Fixer error: {e}")
            traceback.print_exc()
    else:
        print(f"[main] Skipping Fixer — generate_fixes={args.generate_fixes} status={decision.get('status')}")

    # 5) Reporting
    try:
        Reporter(cfg, output_dir).emit(findings_grouped, decision)
    except Exception as e:
        print(f"[reporter] error: {e}")

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
                f.write(f"pipeline_status={decision.get('status','fail')}\n")
                f.write(f"open_pr={'true' if decision.get('open_pr') else 'false'}\n")
        except Exception:
            pass

    # Exit non-zero on fail
    return 1 if decision.get("status") == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())