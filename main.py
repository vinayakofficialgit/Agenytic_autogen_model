# main.py
"""
Enterprise-Grade DevSecOps Agentic AI Pipeline

Features:
- Deterministic orchestration
- Hardened policy enforcement
- Secure target extraction
- LLM-safe execution
- Patch generation only on fail
- CI-stable exit codes
- Canonical decision structure
"""

import argparse
import os
import json
import sys
from pathlib import Path
# from datetime import datetime
from datetime import datetime, UTC
from io import StringIO
import contextlib

try:
    import yaml
except Exception:
    yaml = None


# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


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


def _canonical_stats(findings_grouped: dict) -> dict:
    """Compute deterministic stats independent of policy gate."""
    by_sev = {k: 0 for k in SEVERITY_ORDER}
    total = 0

    for key, items in (findings_grouped or {}).items():
        if key.startswith("_") or not isinstance(items, list):
            continue
        for f in items:
            sev = (f.get("severity") or "low").lower()
            if sev not in by_sev:
                sev = "low"
            by_sev[sev] += 1
            total += 1

    worst = "low"
    for level in SEVERITY_ORDER:
        if by_sev[level] > 0:
            worst = level
            break

    return {
        "total": total,
        "by_severity": by_sev,
        "worst_severity": worst,
    }


def _norm_repo_rel(p: str) -> str:
    if not p:
        return ""
    s = p.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _is_safe_repo_path(path: str, repo_root: Path) -> bool:
    try:
        full = (repo_root / path).resolve()
        return repo_root.resolve() in full.parents or full == repo_root.resolve()
    except Exception:
        return False


def _collect_targets(findings_grouped: dict, repo_root: Path) -> list[str]:
    targets = set()

    for tool, items in (findings_grouped or {}).items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue

            fp = it.get("file") or it.get("path") or it.get("location") or ""
            if isinstance(fp, str) and ":" in fp and not fp.startswith("http"):
                fp = fp.split(":", 1)[0]

            if isinstance(fp, str):
                fp = _norm_repo_rel(fp)
                if fp and _is_safe_repo_path(fp, repo_root):
                    targets.add(fp)

    return sorted(targets)


def _write_targets(output_dir: Path, targets: list[str]) -> Path:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repo_root": ".",
        "targets": targets,
    }
    out = output_dir / "targets.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


# ---------------------------------------------------------------------
# Imports (late binding for robustness)
# ---------------------------------------------------------------------

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


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------

def _load_cfg() -> dict:
    cfg = {
        "inputs": {"reports_dir": "reports", "output_dir": "agent_output"},
        "policy": {
            "remediation": {"auto_pr": True},
            "min_severity_to_fail": os.getenv("MIN_SEVERITY", "high"),
        },
        "llm": {
            "enabled": bool(os.getenv("OLLAMA_URL")),
            "model": os.getenv("LLM_MODEL", "qwen2.5-coder:3b"),
            "temperature": float(os.getenv("OLLAMA_TEMP", "0.2")),
        },
        "normalize_severity": True,
        "write_output": True,
    }

    cfg_path = Path("config/settings.yaml")
    if yaml and cfg_path.exists():
        try:
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            cfg.update(loaded)
        except Exception:
            pass

    return cfg


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    load_env_from_file(".env")

    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-only", action="store_true")
    parser.add_argument("--generate-fixes", action="store_true")
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument("--targets-path", default=None)
    parser.add_argument("--outputs-env", default=os.getenv("GITHUB_OUTPUT"))
    args = parser.parse_args()
    # args = parser.parse_args()


    cfg = _load_cfg()

    reports_dir = Path(cfg["inputs"]["reports_dir"])
    output_dir = Path(cfg["inputs"]["output_dir"])
    repo_root = Path(".").resolve()

    reports_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n🛡️ Enterprise DevSecOps Agentic Pipeline")
    print(f"📅 {datetime.now(UTC).isoformat()}\n")

    # ------------------------------------------------------------
    # 1️⃣ Collect
    # ------------------------------------------------------------
    print("⏳ Collecting findings...")
    try:
        with suppress_verbose_output():
            collector = CollectorAgent(cfg, reports_dir, output_dir)
            findings_grouped = collector.load_all()
            print("DEBUG: findings meta:", findings_grouped.get("_meta"))
    except Exception as e:
        print(f"❌ Collector error: {e}")
        findings_grouped = {}

    stats = _canonical_stats(findings_grouped)

    # ------------------------------------------------------------
    # 2️⃣ Policy Gate
    # ------------------------------------------------------------
    print("⏳ Evaluating policy...")
    try:
        with suppress_verbose_output():
            decision = PolicyGate(cfg, output_dir).decide(findings_grouped)
    except Exception as e:
        decision = {"status": "fail", "reason": f"Policy error: {e}"}

    # Enforce canonical shape
    decision.setdefault("status", "pass")
    decision.setdefault("reason", "")
    decision.setdefault("remediation", {})
    decision["stats"] = stats
    decision["open_pr"] = decision.get("status") == "fail"

    # ------------------------------------------------------------
    # 3️⃣ LLM Analysis
    # ------------------------------------------------------------
    if not args.skip_llm and decision["status"] == "fail":
        print("⏳ Running LLM analysis...")
        try:
            with suppress_verbose_output():
                llm_report = run_autogen_layer(findings_grouped, cfg, output_dir)
            if llm_report:
                decision["remediation"]["llm_report"] = llm_report
                decision["remediation"]["llm_report_path"] = str(output_dir / "llm_report.json")
        except Exception:
            pass

    # ------------------------------------------------------------
    # 4️⃣ Fix generation (only if fail)
    # ------------------------------------------------------------
    if args.generate_fixes and decision["status"] == "fail":
        print("🔧 Generating fixes...")

        targets = _collect_targets(findings_grouped, repo_root)
        _write_targets(output_dir, targets)

        try:
            with suppress_verbose_output():
                Fixer(cfg, output_dir, repo_root=repo_root, targets=targets).apply(findings_grouped)
        except Exception as e:
            print(f"⚠️ Fixer error: {e}")

    else:
        print("ℹ️ Fixer skipped.")

    # ------------------------------------------------------------
    # 5️⃣ Reporting
    # ------------------------------------------------------------
    try:
        with suppress_verbose_output():
            Reporter(cfg, output_dir).emit(findings_grouped, decision)
    except Exception:
        pass

    # ------------------------------------------------------------
    # 6️⃣ Persist decision
    # ------------------------------------------------------------
    (output_dir / "decision.json").write_text(
        json.dumps(decision, indent=2),
        encoding="utf-8",
    )

    if args.outputs_env:
        with open(args.outputs_env, "a", encoding="utf-8") as f:
            f.write(f"pipeline_status={decision['status']}\n")
            f.write(f"open_pr={'true' if decision['open_pr'] else 'false'}\n")

    print(f"\n🚦 Final Status: {decision['status'].upper()}")
    # Always return 0 in CI — security gate will control failure
    if os.getenv("CI_MODE", "1") == "1":
        return 0
    return 1 if decision["status"] == "fail" else 0

    # print(f"\n🚦 Final Status: {decision['status'].upper()}")
    # return 1 if decision["status"] == "fail" else 0

    
    


if __name__ == "__main__":
    sys.exit(main())