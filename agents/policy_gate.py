








# policy_gate.py
"""
Enhanced PolicyGate for DevSecOps Agentic AI Pipeline

Evaluates normalized findings and decides whether to fail the pipeline and/or open a remediation PR.

Key Enhancements:
- Better LLM integration with fallback support
- Improved error handling and logging
- More detailed policy evaluation
- Support for custom severity thresholds

Inputs (flexible):
  - Typically receives `findings` from main.py (CollectorAgent or similar), which may be:
      * a FLAT list of finding dicts, or
      * a GROUPED dict (e.g., {"semgrep":[...], "trivy_fs":[...], ...})
  - OR can read a pre-merged file agent_output/merged_findings.json (when run as __main__)

Outputs:
  - agent_output/decision.json
  - agent_output/policy_summary.md
  - agent_output/policy_explained.md (optional, if LLM_EXPLAIN=1)

Tuning (via environment variables):
  - MIN_SEVERITY => "low|medium|high|critical" (default: "critical")
  - MAX_FINDINGS_TOTAL => integer limit (optional)
  - MAX_PER_CATEGORY_code/infra/image/policy/secrets/webapp => per-category caps
  - ALLOW_TOOLS => comma-separated tools to ignore in gating
  - DENY_TOOLS => comma-separated tools that always count in gating
  - SEVERITY_WEIGHTS => JSON mapping e.g. {"low":1,"medium":2,"high":3,"critical":5}
  - LLM_EXPLAIN => "1" to generate explanations via llm_bridge/Ollama
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

# --- Robust LLM import ---
try:
    from agents.llm_bridge import (
        assistant_factory,
        get_fallback_suggestion,
        check_ollama_health,
    )
except Exception:
    try:
        from llm_bridge import (
            assistant_factory,
            get_fallback_suggestion,
            check_ollama_health,
        )
    except Exception:
        assistant_factory = None
        get_fallback_suggestion = None
        check_ollama_health = None


# --------------------------
# Constants
# --------------------------
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORIES = ("code", "infra", "image", "policy", "secrets", "webapp")


# --------------------------
# Utilities
# --------------------------
def _norm_sev(s: Optional[str]) -> str:
    """Normalize severity to lowercase."""
    return (s or "low").strip().lower()


def _sev_rank(s: Optional[str]) -> int:
    """Get numeric rank for severity."""
    return SEV_ORDER.get(_norm_sev(s), 1)


def _int_env(name: str, default: Optional[int]) -> Optional[int]:
    """Get integer from environment variable."""
    val = os.getenv(name)
    if not val:
        return default
    try:
        return int(val)
    except Exception:
        return default


def _csv_env(name: str) -> List[str]:
    """Get comma-separated list from environment variable."""
    val = os.getenv(name)
    if not val:
        return []
    return [x.strip().lower() for x in val.split(",") if x.strip()]


def _json_env(name: str, default: Dict[str, Any]) -> Dict[str, Any]:
    """Get JSON dict from environment variable."""
    val = os.getenv(name)
    if not val:
        return default
    try:
        return json.loads(val)
    except Exception:
        return default


def _read_json(path: Path) -> Any:
    """Safely read JSON file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _llm_banner() -> str:
    """Small banner showing LLM configuration."""
    url = os.getenv("OLLAMA_URL", "(unset)")
    model = os.getenv("OLLAMA_MODEL", "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


def _llm_ask(name: str, system: str, user: str, temperature: float = 0.2) -> Optional[str]:
    """
    Lightweight helper to ask the LLM.
    Returns None if bridge is unavailable or call fails.
    """
    if assistant_factory is None:
        return None
    
    try:
        agent = assistant_factory(name=name, system_message=system, temperature=temperature)
        messages = [
            {"role": "system", "content": agent.system_message},
            {"role": "user", "content": user},
        ]
        return agent.chat_completion_fn(messages)
    except Exception as e:
        print(f"[policy_gate] LLM error: {e}")
        return None


# --------------------------
# Configuration dataclass
# --------------------------
@dataclass
class PolicyConfig:
    """Policy configuration loaded from environment variables."""
    min_severity: str = "critical"
    max_total: Optional[int] = None
    max_per_category: Optional[Dict[str, int]] = None
    allow_tools: List[str] = field(default_factory=list)
    deny_tools: List[str] = field(default_factory=list)
    severity_weights: Optional[Dict[str, int]] = None


def load_policy_config() -> PolicyConfig:
    """Load policy configuration from environment variables."""
    min_sev = os.getenv("MIN_SEVERITY", "critical
    
                        
                        
                        ").strip().lower()
    max_total = _int_env("MAX_FINDINGS_TOTAL", None)

    # Per-category caps
    per_cat: Dict[str, int] = {}
    for cat in CATEGORIES:
        env_name = f"MAX_PER_CATEGORY_{cat}"
        val = _int_env(env_name, None)
        if val is not None:
            per_cat[cat] = val

    allow_tools = _csv_env("ALLOW_TOOLS")
    deny_tools = _csv_env("DENY_TOOLS")
    sev_weights = _json_env("SEVERITY_WEIGHTS", {"low": 1, "medium": 2, "high": 3, "critical": 4})

    return PolicyConfig(
        min_severity=min_sev,
        max_total=max_total,
        max_per_category=per_cat if per_cat else None,
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        severity_weights=sev_weights,
    )


# --------------------------
# Input normalization
# --------------------------
_GROUP_TO_CATEGORY = {
    "semgrep": "code",
    "trivy_fs": "infra",
    "trivy_image": "image",
    "tfsec": "infra",
    "gitleaks": "secrets",
    "conftest": "policy",
    "zap": "webapp",
}


def _as_location(f: Dict[str, Any]) -> str:
    """Extract location string from finding."""
    loc = (f.get("location") or "").strip()
    if loc:
        return loc
    file = (f.get("file") or f.get("path") or "").strip()
    line = f.get("line")
    if file and line:
        try:
            return f"{file}:{int(line)}"
        except Exception:
            return f"{file}:{line}"
    return file or ""


def _flatten_findings_input(findings: Union[List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Accepts either flat list or grouped dict.
    Returns a flattened list with normalized fields.
    """
    flat: List[Dict[str, Any]] = []
    
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            g = dict(f)
            g["severity"] = _norm_sev(g.get("severity"))
            g["tool"] = (g.get("tool") or g.get("source") or "").strip().lower()
            if not g.get("category"):
                g["category"] = _GROUP_TO_CATEGORY.get(g["tool"], "")
            if not g.get("location"):
                g["location"] = _as_location(g)
            flat.append(g)
        return flat

    if isinstance(findings, dict):
        for group, items in findings.items():
            if group.startswith("_"):
                continue
            if not isinstance(items, list):
                continue
            tool = group.lower()
            category = _GROUP_TO_CATEGORY.get(tool, "")
            for it in items:
                if not isinstance(it, dict):
                    continue
                g = dict(it)
                g["severity"] = _norm_sev(g.get("severity"))
                g["tool"] = tool
                g["category"] = g.get("category") or category
                g["location"] = g.get("location") or _as_location(g)
                g["id"] = g.get("id") or g.get("rule_id") or g.get("check_id")
                g["message"] = g.get("message") or g.get("summary") or g.get("title") or g.get("description") or ""
                flat.append(g)
        return flat

    return []


# --------------------------
# Scoring & gating
# --------------------------
def summarize(findings: List[Dict[str, Any]], cfg: PolicyConfig) -> Dict[str, Any]:
    """Generate summary statistics from findings."""
    counts_by_sev: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    counts_by_cat: Dict[str, int] = {c: 0 for c in CATEGORIES}
    counts_by_tool: Dict[str, int] = {}
    worst_rank = 0

    total = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = _norm_sev(f.get("severity"))
        cat = (f.get("category") or "").strip().lower()
        tool = (f.get("tool") or f.get("source") or "").strip().lower()

        total += 1
        counts_by_sev[sev] = counts_by_sev.get(sev, 0) + 1
        if cat in counts_by_cat:
            counts_by_cat[cat] += 1
        counts_by_tool[tool] = counts_by_tool.get(tool, 0) + 1
        worst_rank = max(worst_rank, _sev_rank(sev))

    worst_sev = next((k for k, v in SEV_ORDER.items() if v == worst_rank), "low")

    # Weighted score
    weights = cfg.severity_weights or SEV_ORDER
    weighted_score = (
        counts_by_sev["low"] * weights.get("low", 1)
        + counts_by_sev["medium"] * weights.get("medium", 2)
        + counts_by_sev["high"] * weights.get("high", 3)
        + counts_by_sev["critical"] * weights.get("critical", 4)
    )

    return {
        "total": total,
        "by_severity": counts_by_sev,
        "by_category": counts_by_cat,
        "by_tool": counts_by_tool,
        "worst_severity": worst_sev,
        "weighted_score": weighted_score,
    }


def gate(
    stats: Dict[str, Any],
    findings: List[Dict[str, Any]],
    cfg: PolicyConfig
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Evaluate findings against policy.
    Returns (should_fail, reason, violations).
    """
    min_rank = _sev_rank(cfg.min_severity)
    allow = set(cfg.allow_tools or [])
    deny = set(cfg.deny_tools or [])
    violations: List[Dict[str, Any]] = []

    # 1) Severity gate
    for f in findings:
        if not isinstance(f, dict):
            continue
        tool = (f.get("tool") or f.get("source") or "").strip().lower()
        sev_rank = _sev_rank(f.get("severity"))
        
        # Apply allow/deny filter
        if tool in allow and tool not in deny:
            continue
        
        if sev_rank >= min_rank:
            violation = {
                "tool": tool,
                "severity": f.get("severity"),
                "category": f.get("category"),
                "location": f.get("location") or _as_location(f),
                "id": f.get("id"),
                "message": f.get("message"),
            }
            violations.append(violation)

    if violations:
        first = violations[0]
        reason = (
            f"Found {first.get('severity')} (>= {cfg.min_severity}) from {first.get('tool')}"
            + (f" at {first['location']}" if first.get("location") else "")
        )
        return True, reason, violations

    # 2) Total cap
    if cfg.max_total is not None and stats["total"] > cfg.max_total:
        return True, f"Total findings {stats['total']} exceed cap {cfg.max_total}", []

    # 3) Per-category caps
    if cfg.max_per_category:
        for cat, cap in cfg.max_per_category.items():
            if cap is None:
                continue
            count = stats["by_category"].get(cat, 0)
            if count > cap:
                return True, f"Category '{cat}' findings {count} exceed cap {cap}", []

    return False, "Within policy", []


# --------------------------
# PolicyGate class
# --------------------------
class PolicyGate:
    """
    Main policy evaluation class.
    
    Usage:
        decision = PolicyGate(cfg, output_dir).decide(findings)
    """

    def __init__(self, cfg: Dict[str, Any], output_dir: Path):
        self.cfg = cfg or {}
        self.out_dir = Path(output_dir)

    def _maybe_llm_explain(self, stats: Dict[str, Any], reason: str, violations: List[Dict[str, Any]]) -> Optional[str]:
        """Generate LLM explanation if enabled."""
        if os.getenv("LLM_EXPLAIN", "").strip() != "1":
            return None

        system = (
            "You are a DevSecOps policy assistant. "
            "Explain briefly why the pipeline passed or failed based on the provided stats and reason. "
            "Be factual, concise (<= 150 words), and avoid hallucinations."
        )
        
        user = (
            f"Stats (JSON):\n{json.dumps(stats, indent=2)}\n\n"
            f"Decision Reason: {reason}\n\n"
            f"Violations ({len(violations)}):\n{json.dumps(violations[:3], indent=2) if violations else 'None'}"
        )

        text = _llm_ask(
            name="policy_explainer",
            system=system,
            user=user,
            temperature=0.2,
        )
        
        if text:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            path = self.out_dir / "policy_explained.md"
            try:
                # Check if it's a fallback response
                is_fallback = "[Fallback" in text
                content = _llm_banner()
                if is_fallback:
                    content += "> ⚠️ Note: Using fallback explanation (LLM unavailable)\n\n"
                content += text
                path.write_text(content, encoding="utf-8")
                return str(path)
            except Exception as e:
                print(f"[policy_gate] Error writing explanation: {e}")
        
        return None

    def _maybe_attach_llm_report_path(self, decision: Dict[str, Any]) -> None:
        """Attach LLM report path if it exists."""
        try:
            p = self.out_dir / "llm_report.json"
            if p.exists():
                decision.setdefault("remediation", {})
                decision["remediation"]["llm_report_path"] = str(p)
        except Exception:
            pass

    def _write_outputs(
        self,
        should_fail: bool,
        reason: str,
        stats: Dict[str, Any],
        violations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Write decision outputs to files."""
        self.out_dir.mkdir(parents=True, exist_ok=True)

        decision = {
            "open_pr": bool(should_fail),
            "status": "fail" if should_fail else "ok",
            "reason": reason,
            "stats": stats,
            "violations": violations[:10],  # Include top 10 for context
        }

        # Write decision.json
        try:
            (self.out_dir / "decision.json").write_text(
                json.dumps(decision, indent=2), encoding="utf-8"
            )
        except Exception as e:
            print(f"[policy_gate] Error writing decision.json: {e}")

        # Build markdown summary
        md = [
            "# Policy Gate Summary",
            "",
            f"**Status:** {'❌ FAIL' if should_fail else '✅ PASS'}",
            f"**Reason:** {reason}",
            "",
            "## Stats",
            f"- Total: {stats['total']}",
            f"- Worst severity: {stats['worst_severity']}",
            f"- Weighted score: {stats['weighted_score']}",
            "",
            "### By Severity",
        ]
        for k in ("critical", "high", "medium", "low"):
            count = stats['by_severity'].get(k, 0)
            icon = "🔴" if k == "critical" else "🟠" if k == "high" else "🟡" if k == "medium" else "🟢"
            md.append(f"  - {icon} {k}: {count}")

        md.append("")
        md.append("### By Category")
        for c in CATEGORIES:
            md.append(f"  - {c}: {stats['by_category'].get(c, 0)}")

        md.append("")
        md.append("### By Tool")
        for tool, count in sorted(stats["by_tool"].items(), key=lambda x: -x[1])[:10]:
            md.append(f"  - {tool or '<unknown>'}: {count}")

        # Violations section
        if violations:
            md.append("")
            md.append("## Violations")
            for i, v in enumerate(violations[:10], 1):
                sev = v.get('severity', '')
                sev_icon = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "🟢"
                line = f"{i}. {sev_icon} **[{sev.upper()}]** {v.get('tool','')} @ `{v.get('location','')}`"
                if v.get("id"):
                    line += f" (id: `{v['id']}`)"
                md.append(line)
                if v.get("message"):
                    md.append(f"   - {v['message'][:200]}")

        # Write summary
        try:
            (self.out_dir / "policy_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
        except Exception as e:
            print(f"[policy_gate] Error writing summary: {e}")

        # Optional LLM explanation
        explained_path = self._maybe_llm_explain(stats, reason, violations)
        if explained_path:
            decision["policy_explained_md"] = explained_path

        # Attach LLM report path if exists
        self._maybe_attach_llm_report_path(decision)

        return decision

    def decide(self, findings_input: Union[List[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate findings against policy and return decision.
        
        Args:
            findings_input: Either flat list or grouped dict of findings
            
        Returns:
            Decision dict with status, reason, stats, violations
        """
        # Normalize input
        findings = _flatten_findings_input(findings_input)
        print(f"[policy_gate] Evaluating {len(findings)} findings...")

        # Load config
        policy_cfg = load_policy_config()
        print(f"[policy_gate] Policy: min_severity={policy_cfg.min_severity}, max_total={policy_cfg.max_total}")

        # Summarize and gate
        stats = summarize(findings, policy_cfg)
        should_fail, reason, violations = gate(stats, findings, policy_cfg)

        print(f"[policy_gate] Decision: {'FAIL' if should_fail else 'PASS'} - {reason}")
        if violations:
            print(f"[policy_gate] Found {len(violations)} violation(s)")

        return self._write_outputs(should_fail, reason, stats, violations)


# --------------------------
# CLI entry point
# --------------------------
if __name__ == "__main__":
    out_dir = Path("agent_output")
    out_dir.mkdir(parents=True, exist_ok=True)

    findings_input: Union[List[Dict[str, Any]], Dict[str, Any]] = []
    
    # Try to load findings from various sources
    grouped_path = Path("agent_output/findings_grouped.json")
    merged = Path("agent_output/merged_findings.json")

    if grouped_path.exists():
        data = _read_json(grouped_path)
        if isinstance(data, dict):
            findings_input = data
            print(f"[policy_gate] Loaded grouped findings from {grouped_path}")
    elif merged.exists():
        data = _read_json(merged)
        if isinstance(data, dict) and "findings" in data:
            findings_input = data.get("findings") or []
        elif isinstance(data, list):
            findings_input = data
        print(f"[policy_gate] Loaded merged findings from {merged}")
    else:
        # Try to collect from reports
        try:
            try:
                from agents.collector import CollectorAgent
            except Exception:
                from collector import CollectorAgent
            agent = CollectorAgent({"dedup_keys": ["tool", "id", "location"]}, Path("reports"), out_dir)
            findings_input = agent.load_all()
            print("[policy_gate] Collected findings from reports/")
        except Exception as e:
            print(f"[policy_gate] Warning: could not collect findings: {e}")
            findings_input = []

    decision = PolicyGate({}, out_dir).decide(findings_input)
    print(f"\nDecision: {json.dumps(decision, indent=2)}")
    sys.exit(1 if decision.get("status") == "fail" else 0)
