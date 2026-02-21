"""
PolicyGate — deterministic security gate with optional AI enrichment

Responsibilities:
- Normalize findings
- Apply policy thresholds
- Merge AI enrichment safely
- Compute risk score
- Decide PASS / FAIL
- Produce structured decision.json
"""

from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional

# -------------------------------------------------
# Severity order (canonical)
# -------------------------------------------------
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# -------------------------------------------------
# Category mapping (scanner → category)
# -------------------------------------------------
GROUP_TO_CATEGORY = {
    "semgrep": "code",
    "spotbugs": "code",
    "trivy_fs": "infra",
    "tfsec": "infra",
    "trivy_image": "image",
    "gitleaks": "secrets",
    "conftest": "policy",
    "zap": "webapp",
    "dependency-check": "sca",
    "dependency_check": "sca",
}

# -------------------------------------------------
# Utility functions
# -------------------------------------------------
def _norm_sev(s: Optional[str]) -> str:
    """Normalize severity safely."""
    return (s or "low").strip().lower()

def _sev_rank(s: Optional[str]) -> int:
    """Convert severity into numeric rank."""
    return SEV_ORDER.get(_norm_sev(s), 1)

def _as_location(f: Dict[str, Any]) -> str:
    """Create unified location string."""
    file = f.get("file") or f.get("path") or ""
    line = f.get("line")
    return f"{file}:{line}" if file and line else file

# -------------------------------------------------
# Policy configuration
# -------------------------------------------------
@dataclass
class PolicyConfig:
    min_severity: str = "critical"
    max_total: Optional[int] = None
    max_per_category: Optional[Dict[str, int]] = None
    allow_tools: List[str] = field(default_factory=list)
    deny_tools: List[str] = field(default_factory=list)
    severity_weights: Optional[Dict[str, int]] = None
    risk_threshold: int = 12

def load_policy_config() -> PolicyConfig:
    """Load policy from environment variables."""
    return PolicyConfig(
        min_severity=os.getenv("MIN_SEVERITY", "critical").lower(),
        max_total=int(os.getenv("MAX_FINDINGS_TOTAL", "0") or 0) or None,
        allow_tools=[x.strip() for x in os.getenv("ALLOW_TOOLS", "").split(",") if x],
        deny_tools=[x.strip() for x in os.getenv("DENY_TOOLS", "").split(",") if x],
        severity_weights=json.loads(os.getenv("SEVERITY_WEIGHTS", json.dumps(SEV_ORDER))),
        risk_threshold=int(os.getenv("AI_RISK_THRESHOLD", "12")),
    )

# -------------------------------------------------
# Flatten grouped findings
# -------------------------------------------------
def _flatten_findings(grouped):
    """Convert grouped findings into flat normalized list."""
    flat = []
    for tool, items in grouped.items():
        if not isinstance(items, list):
            continue
        for f in items:
            g = dict(f)
            g["tool"] = tool
            g["severity"] = _norm_sev(g.get("severity"))
            g["category"] = g.get("category") or GROUP_TO_CATEGORY.get(tool, "misc")
            g["location"] = g.get("location") or _as_location(g)
            g["id"] = g.get("id") or g.get("rule_id") or g.get("title")
            flat.append(g)
    return flat

# -------------------------------------------------
# AI risk scoring
# -------------------------------------------------
def _ai_risk_score(f):
    """Compute AI risk score using enrichment fields."""
    sev = _sev_rank(f.get("severity"))
    exploit = 2 if f.get("exploitability") == "high" else 1
    reach = 2 if f.get("reachability") == "public" else 1
    biz = 2 if f.get("business_impact") == "high" else 1
    chain = 2 if f.get("chain") else 1
    return sev * exploit * reach * biz * chain

# -------------------------------------------------
# Summarization
# -------------------------------------------------
def summarize(findings, cfg):
    """Compute aggregated statistics."""
    by_sev = {k: 0 for k in SEV_ORDER}
    by_cat = {}
    by_tool = {}
    worst = "low"

    for f in findings:
        sev = _norm_sev(f.get("severity"))
        cat = f.get("category", "misc")
        tool = f.get("tool", "unknown")

        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_cat[cat] = by_cat.get(cat, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1

        if _sev_rank(sev) > _sev_rank(worst):
            worst = sev

    weights = cfg.severity_weights or SEV_ORDER
    score = sum(by_sev[k] * weights.get(k, 1) for k in by_sev)

    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
        "by_tool": by_tool,
        "worst_severity": worst,
        "weighted_score": score,
    }

# -------------------------------------------------
# Gate logic
# -------------------------------------------------
def gate(stats, findings, cfg):
    """Evaluate findings against policy."""
    violations = []

    for f in findings:
        tool = f.get("tool")

        # deny overrides allow
        if tool in cfg.deny_tools:
            pass
        elif tool in cfg.allow_tools:
            continue

        if f.get("noise"):
            continue

        risk = _ai_risk_score(f)
        sev_rank = _sev_rank(f.get("severity"))

        if risk >= cfg.risk_threshold or sev_rank >= _sev_rank(cfg.min_severity):
            violations.append({
                "tool": tool,
                "severity": f.get("severity"),
                "risk": risk,
                "category": f.get("category"),
                "location": f.get("location"),
                "id": f.get("id"),
                "message": f.get("message"),
            })

    # exploit chain detection
    if any(f.get("chain") for f in findings):
        return True, "Exploit chain detected", violations

    if violations:
        return True, f"{violations[0]['severity']} violation detected", violations

    if cfg.max_total and stats["total"] > cfg.max_total:
        return True, "Total findings exceed cap", []

    return False, "Within policy", []

# -------------------------------------------------
# PolicyGate class
# -------------------------------------------------
class PolicyGate:
    """Main PolicyGate engine."""

    def __init__(self, cfg=None, output_dir=None):
        self.cfg = load_policy_config()
        self.output_dir = output_dir

    def decide(self, grouped):
        flat = _flatten_findings(grouped)
        stats = summarize(flat, self.cfg)
        violated, reason, violations = gate(stats, flat, self.cfg)

        decision = {
            "decision": "FAIL" if violated else "PASS",
            "reason": reason,
            "stats": stats,
            "violations": violations[:20],
        }

        if self.output_dir:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            (Path(self.output_dir) / "decision.json").write_text(json.dumps(decision, indent=2))

        return decision

# -------------------------------------------------
# CLI debug mode
# -------------------------------------------------
if __name__ == "__main__":
    merged = Path("agent_output/merged_findings.json")
    findings = json.loads(merged.read_text()).get("findings", []) if merged.exists() else []
    decision = PolicyGate({}, Path("agent_output")).decide(findings)
    print(json.dumps(decision, indent=2))
    sys.exit(1 if decision["decision"] == "FAIL" else 0)