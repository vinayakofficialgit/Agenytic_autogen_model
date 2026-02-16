# main.py
"""
DevSecOps Agentic AI Pipeline - Deterministic analysis + targeted fix generation

Key upgrades:
- Writes agent_output/targets.json containing exact repo-relative vulnerable file paths
- Fix phase reads targets.json and ONLY patches those paths (no ambiguity)
- Keeps analysis-only and generate-fixes deterministic and CI-friendly
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


def _load_cfg() -> dict:
    default_cfg = {
        "inputs": {"reports_dir": "reports", "output_dir": "agent_output"},
        "policy": {
            "remediation": {"auto_pr": True},
            "min_severity_to_fail": os.getenv("MIN_SEVERITY", "high"),
        },
        "llm": {
            "enabled": bool(os.getenv("OLLAMA_URL") or os.getenv("OLLAMA_HOST"))
                       or (os.getenv("LLM_ENABLED", "").strip() == "1"),
            "model": os.getenv("LLM_MODEL", "qwen2.5-coder:3b"),
            "temperature": float(os.getenv("OLLAMA_TEMPERATURE", os.getenv("OLLAMA_TEMP", "0.2"))),
        },
        "remediation": {
            "defaults": {
                "docker_nonroot_user": "appuser",
                "k8s_default_cpu_limit": "250m",
                "k8s_default_mem_limit": "256Mi",
                "terraform_allowed_cidr": "10.0.0.0/24",
            },
            # IMPORTANT: only patch stored targets unless targets missing/empty
            "targeted_only": True,
        },
        "dedup_keys": ["tool", "id", "location"],
        "normalize_severity": True,
        "write_output": True,
    }

    cfg_path = Path("config/settings.yaml")
    if yaml and cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            for k, v in loaded.items():
                if isinstance(v, dict) and isinstance(default_cfg.get(k), dict):
                    default_cfg[k].update(v)
                else:
                    default_cfg[k] = v
        except Exception:
            pass

    return default_cfg


def print_banner():
    if not os.getenv("OLLAMA_URL") and os.getenv("OLLAMA_HOST"):
        os.environ["OLLAMA_URL"] = f"http://{os.getenv('OLLAMA_HOST')}"
    print("\n" + "=" * 70)
    print("   🛡️  DevSecOps Agentic AI Security Scanner")
    print("=" * 70)
    print(f"   📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   🤖 LLM: {os.getenv('LLM_MODEL', 'qwen2.5-coder:3b')} @ {os.getenv('OLLAMA_URL', 'localhost:11434')}")
    print("=" * 70 + "\n")


def _norm_repo_rel(p: str) -> str:
    """Normalize to repo-relative POSIX path as best-effort."""
    if not p:
        return ""
    s = p.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _collect_targets(findings_grouped: dict) -> list[str]:
    """
    Extract exact vulnerable file paths from findings.
    Output is unique repo-relative paths.
    """
    targets: set[str] = set()

    for tool, items in (findings_grouped or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            fp = it.get("file") or it.get("path") or it.get("location") or ""
            # Some tools keep location as "path:line"
            if isinstance(fp, str) and ":" in fp and not fp.startswith("http"):
                # keep left side if it looks like file path
                left = fp.split(":", 1)[0]
                if "/" in left or left.endswith((".py", ".js", ".yaml", ".yml", ".html", ".tf", "Dockerfile")):
                    fp = left
            if isinstance(fp, str):
                fp = _norm_repo_rel(fp)
                if fp:
                    targets.add(fp)

    # Also include known infra dirs if findings exist there (optional; conservative)
    return sorted(targets)


def _write_targets(output_dir: Path, targets: list[str]) -> Path:
    """
    Write targets.json for the fix job to consume.
    """
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repo_root": ".",
        "targets": targets,
    }
    out = output_dir / "targets.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


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

    # IMPORTANT: allows fix job to explicitly point at previous targets
    parser.add_argument("--targets-path", default=None, help="Path to targets.json (default: agent_output/targets.json)")

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

    reports_dir = Path(cfg["inputs"]["reports_dir"])
    output_dir = Path(cfg["inputs"]["output_dir"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1) Collect findings
    print("   ⏳ Scanning...")
    try:
        with suppress_verbose_output():
            collector = CollectorAgent(cfg, reports_dir, output_dir)
            findings_grouped = collector.load_all()
    except Exception as e:
        print(f"   ❌ Error: {e}")
        findings_grouped = {}

    (output_dir / "merged_findings.json").write_text(
        json.dumps({"findings": findings_grouped}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 1b) Persist target files (exact file paths)
    targets = _collect_targets(findings_grouped)
    targets_file = _write_targets(output_dir, targets)
    print(f"[targets] recorded {len(targets)} file(s) -> {targets_file}")

    # 2) Policy Gate
    print("   ⏳ Evaluating policy...")
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

    # 4) Fix generation (only when requested AND failed)
    try:
        if args.generate_fixes and decision.get("status") == "fail":
            print("[main] Fixer condition met: --generate-fixes and status=fail")

            # Prefer explicit targets-path if provided; else default to agent_output/targets.json
            tpath = args.targets_path or str(output_dir / "targets.json")
            tfile = Path(tpath)
            if not tfile.exists():
                # Fall back to current run targets.json
                tfile = output_dir / "targets.json"

            fixer_targets: list[str] = []
            try:
                data = json.loads(tfile.read_text(encoding="utf-8"))
                fixer_targets = [str(x) for x in (data.get("targets") or []) if x]
            except Exception:
                fixer_targets = []

            with suppress_verbose_output():
                fix_info = Fixer(cfg, output_dir, repo_root=Path("."), targets=fixer_targets).apply(findings_grouped)

            # Diagnostics: show how many patches were produced
            patch_dir = output_dir / "patches"
            patch_list = list(patch_dir.glob("*.patch"))
            print(f"[fixer] patches generated: {len(patch_list)}")
            for p in patch_list:
                print(f"[fixer]  - {p}")

            decision.setdefault("remediation", {})
            if isinstance(fix_info, dict):
                for k, v in fix_info.items():
                    if k != "llm_report" and (v is not None or k not in decision["remediation"]):
                        decision["remediation"][k] = v
        else:
            print(f"[main] Skipping Fixer — args.generate_fixes={getattr(args,'generate_fixes',None)} "
                  f"status={decision.get('status')}")
    except Exception as e:
        print(f"[main] Fixer block error: {e}")

    # 5) Reporting
    try:
        with suppress_verbose_output():
            Reporter(cfg, output_dir).emit(findings_grouped, decision)
    except Exception:
        pass

    # 6) Write decision
    (output_dir / "decision.json").write_text(
        json.dumps(decision, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # GitHub step outputs
    if args.outputs_env:
        try:
            with open(args.outputs_env, "a", encoding="utf-8") as f:
                f.write(f"pipeline_status={decision.get('status','ok')}\n")
                f.write(f"open_pr={'true' if decision.get('open_pr') else 'false'}\n")
        except Exception:
            pass

    return 1 if decision.get("status") == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())