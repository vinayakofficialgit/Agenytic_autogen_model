# main.py
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

# severity ranking
try:
    from agents.policy_gate import _sev_rank
except Exception:
    from policy_gate import _sev_rank

# core imports
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


def load_env_from_file(env_file=".env", override=False):
    p = Path(env_file)
    if not p.exists():
        return
    for raw in p.read_text().splitlines():
        if "=" in raw:
            k, v = raw.split("=", 1)
            if override or k not in os.environ:
                os.environ[k.strip()] = v.strip()


@contextlib.contextmanager
def suppress():
    if os.getenv("LLM_VERBOSE") == "1":
        yield
    else:
        old = sys.stdout
        sys.stdout = StringIO()
        yield
        sys.stdout = old


def _load_cfg():
    return {
        "inputs": {"reports_dir": "reports", "output_dir": "agent_output"},
        "policy": {"min_severity_to_fail": os.getenv("MIN_SEVERITY", "critical")},
    }


def print_banner():
    print("\n=== DevSecOps Agentic AI Orchestrator ===")
    print(datetime.now())
    print("=========================================\n")


def main():
    load_env_from_file()

    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir")
    parser.add_argument("--output-dir")
    parser.add_argument("--min-severity")
    parser.add_argument("--skip-llm", action="store_true")
    args = parser.parse_args()

    print_banner()

    cfg = _load_cfg()

    reports_dir = Path(args.reports_dir or cfg["inputs"]["reports_dir"])
    output_dir = Path(args.output_dir or cfg["inputs"]["output_dir"])
    min_sev = (args.min_severity or cfg["policy"]["min_severity_to_fail"]).lower()

    reports_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    # =======================
    # 1️⃣ Collector
    # =======================
    with suppress():
        collector = CollectorAgent(cfg, reports_dir, output_dir)
        grouped = collector.load_all()

    # remove meta
    grouped = {k: v for k, v in grouped.items() if not k.startswith("_")}

    # flatten safety
    for tool in list(grouped.keys()):
        grouped[tool] = [x for x in grouped[tool] if isinstance(x, dict)]

    # =======================
    # 2️⃣ Policy Gate
    # =======================
    decision = PolicyGate(cfg, output_dir).decide(grouped)

    # normalize decision schema
    if "decision" not in decision:
        decision["decision"] = "FAIL" if decision.get("status") == "fail" else "PASS"

    # =======================
    # 3️⃣ AI analysis
    # =======================
    if not args.skip_llm:
        try:
            with suppress():
                run_autogen_layer(grouped, cfg, output_dir)
        except Exception:
            pass

    # =======================
    # 4️⃣ Auto fix
    # =======================
    if decision.get("decision") == "FAIL":
        try:
            with suppress():
                Fixer(cfg, output_dir).apply(grouped)
        except Exception:
            pass

    # =======================
    # 5️⃣ Reporting
    # =======================
    Reporter(cfg, output_dir).emit(grouped, decision)

    # =======================
    # 6️⃣ Write decision.json
    # =======================
    with open(output_dir / "decision.json", "w") as f:
        json.dump(decision, f, indent=2)

    print("\nPipeline:", decision["decision"])

    return 1 if decision["decision"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())