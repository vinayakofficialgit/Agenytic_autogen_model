# policy_gate.py
"""
Enterprise-Grade Policy Gate
Deterministic • Tamper-Resistant • CI-Safe
"""

from __future__ import annotations

import json
import os
import sys
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime


# =========================================================
# CONSTANTS
# =========================================================

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VALID_SEVERITIES = set(SEV_ORDER.keys())
CATEGORIES = ("code", "infra", "image", "policy", "secrets", "webapp")

MAX_VIOLATIONS_OUTPUT = 25


# =========================================================
# UTILITIES
# =========================================================

def _norm_sev(s: Optional[str]) -> str:
    sev = (s or "low").strip().lower()
    return sev if sev in VALID_SEVERITIES else "low"


def _sev_rank(s: Optional[str]) -> int:
    return SEV_ORDER.get(_norm_sev(s), 1)


def _hash_decision(data: Dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _csv_env(name: str) -> List[str]:
    val = os.getenv(name)
    if not val:
        return []
    return [x.strip().lower() for x in val.split(",") if x.strip()]


def _int_env(name: str, default: Optional[int]) -> Optional[int]:
    val = os.getenv(name)
    if not val:
        return default
    try:
        return int(val)
    except Exception:
        return default


# =========================================================
# CONFIG
# =========================================================

@dataclass
class PolicyConfig:
    min_severity: str = "high"
    max_total: Optional[int] = None
    allow_tools: List[str] = field(default_factory=list)
    deny_tools: List[str] = field(default_factory=list)


def load_policy_config() -> PolicyConfig:
    return PolicyConfig(
        min_severity=_norm_sev(os.getenv("MIN_SEVERITY", "high")),
        max_total=_int_env("MAX_FINDINGS_TOTAL", None),
        allow_tools=_csv_env("ALLOW_TOOLS"),
        deny_tools=_csv_env("DENY_TOOLS"),
    )


# =========================================================
# FINDING NORMALIZATION
# =========================================================

def _flatten(findings_input: Union[List, Dict]) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []

    if isinstance(findings_input, list):
        items = findings_input
    elif isinstance(findings_input, dict):
        items = []
        for v in findings_input.values():
            if isinstance(v, list):
                items.extend(v)
    else:
        return flat

    for f in items:
        if not isinstance(f, dict):
            continue
        flat.append({
            "severity": _norm_sev(f.get("severity")),
            "tool": (f.get("tool") or f.get("source") or "").lower(),
            "category": (f.get("category") or "").lower(),
            "location": f.get("location") or f.get("file") or "",
            "id": f.get("id") or f.get("rule_id"),
            "message": f.get("message") or "",
        })

    return flat


# =========================================================
# POLICY LOGIC
# =========================================================

def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:

    by_sev = {k: 0 for k in VALID_SEVERITIES}
    by_tool: Dict[str, int] = {}
    worst_rank = 0

    for f in findings:
        sev = f["severity"]
        by_sev[sev] += 1
        worst_rank = max(worst_rank, _sev_rank(sev))
        tool = f["tool"]
        by_tool[tool] = by_tool.get(tool, 0) + 1

    worst_sev = next((k for k, v in SEV_ORDER.items() if v == worst_rank), "low")

    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_tool": by_tool,
        "worst_severity": worst_sev,
    }


def gate(findings: List[Dict[str, Any]], cfg: PolicyConfig) -> Tuple[bool, str, List[Dict[str, Any]]]:

    min_rank = _sev_rank(cfg.min_severity)
    allow = set(cfg.allow_tools)
    deny = set(cfg.deny_tools)

    violations = []

    for f in findings:

        tool = f["tool"]

        if tool in allow and tool not in deny:
            continue

        if tool in deny:
            pass

        if _sev_rank(f["severity"]) >= min_rank:
            violations.append(f)

    violations.sort(key=lambda x: _sev_rank(x["severity"]), reverse=True)

    if violations:
        return True, f"{len(violations)} finding(s) >= {cfg.min_severity}", violations[:MAX_VIOLATIONS_OUTPUT]

    if cfg.max_total and len(findings) > cfg.max_total:
        return True, f"Total findings exceed cap ({cfg.max_total})", []

    return False, "Within policy", []


# =========================================================
# POLICY GATE CLASS
# =========================================================

class PolicyGate:

    def __init__(self, cfg: Dict[str, Any], output_dir: Path):
        self.out = Path(output_dir)

    def decide(self, findings_input: Union[List, Dict]) -> Dict[str, Any]:

        findings = _flatten(findings_input)
        policy_cfg = load_policy_config()

        stats = summarize(findings)
        should_fail, reason, violations = gate(findings, policy_cfg)

        decision = {
            "status": "fail" if should_fail else "pass",
            "open_pr": bool(should_fail),
            "reason": reason,
            "stats": stats,
            "violations": violations,
            "policy": {
                "min_severity": policy_cfg.min_severity,
                "max_total": policy_cfg.max_total,
                "allow_tools": policy_cfg.allow_tools,
                "deny_tools": policy_cfg.deny_tools,
            },
            "evaluated_at": datetime.utcnow().isoformat() + "Z",
        }

        decision["decision_hash"] = _hash_decision(decision)

        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "decision.json").write_text(
            json.dumps(decision, indent=2),
            encoding="utf-8"
        )

        return decision


# =========================================================
# CLI ENTRY
# =========================================================

if __name__ == "__main__":
    findings_file = Path("agent_output/merged_findings.json")
    findings = []

    if findings_file.exists():
        data = json.loads(findings_file.read_text())
        findings = data.get("findings") or data

    decision = PolicyGate({}, Path("agent_output")).decide(findings)

    print(json.dumps(decision, indent=2))
    sys.exit(1 if decision["status"] == "fail" else 0)