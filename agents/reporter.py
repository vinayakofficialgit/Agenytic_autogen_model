# agents/reporter.py
"""
Enterprise-Grade Reporter
Deterministic, CI-safe, LLM-hardened
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Union
import json
import os


SEVERITY_ORDER = ["critical", "high", "medium", "low"]

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "warning": "medium",
}


def _normalize_severity(value: str) -> str:
    if not isinstance(value, str):
        return "low"
    return SEVERITY_MAP.get(value.strip().lower(), "low")


class Reporter:

    def __init__(self, config: Dict[str, Any], output_dir: Path):
        self.cfg = config or {}
        self.out = Path(output_dir)

    # ---------------------------------------------------
    # Flatten grouped
    # ---------------------------------------------------

    def _flatten(self, findings_input: Union[List, Dict]) -> List[Dict[str, Any]]:
        if isinstance(findings_input, list):
            return [f for f in findings_input if isinstance(f, dict)]

        if isinstance(findings_input, dict):
            flat = []
            for k, v in findings_input.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, list):
                    flat.extend([f for f in v if isinstance(f, dict)])
            return flat

        return []

    # ---------------------------------------------------
    # Safe Markdown
    # ---------------------------------------------------

    def _safe_md(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        return text.replace("```", "'''").replace("<script", "&lt;script")

    # ---------------------------------------------------
    # Main Emit
    # ---------------------------------------------------

    def emit(self, findings_input: Union[List, Dict], decision: Dict[str, Any]):
        self.out.mkdir(parents=True, exist_ok=True)

        findings = self._flatten(findings_input)

        counts_by_tool = {}
        counts_by_severity = {}

        for f in findings:
            tool = f.get("tool", "unknown")
            counts_by_tool[tool] = counts_by_tool.get(tool, 0) + 1

            sev = _normalize_severity(f.get("severity", "low"))
            counts_by_severity[sev] = counts_by_severity.get(sev, 0) + 1

        worst = "low"
        for level in SEVERITY_ORDER:
            if counts_by_severity.get(level, 0) > 0:
                worst = level
                break

        metrics = {
            "counts_by_tool": counts_by_tool,
            "counts_by_severity": counts_by_severity,
            "total_findings": len(findings),
            "worst_severity": worst,
            "gate_status": decision.get("status"),
            "reason": decision.get("reason"),
        }

        (self.out / "metrics.json").write_text(
            json.dumps(metrics, indent=2),
            encoding="utf-8"
        )

        # ------------------------------
        # PR Comment (Deterministic)
        # ------------------------------

        status = decision.get("status", "ok")
        icon = "❌" if status == "fail" else "✅"

        pr_lines = [
            f"## 🛡️ Security Scan — {icon} {'Fail' if status=='fail' else 'Pass'}",
            "",
            f"**Total Findings:** {len(findings)}",
            f"**Worst Severity:** {worst}",
            "",
            "### Severity Breakdown",
            f"- 🔴 Critical: {counts_by_severity.get('critical', 0)}",
            f"- 🟠 High: {counts_by_severity.get('high', 0)}",
            f"- 🟡 Medium: {counts_by_severity.get('medium', 0)}",
            f"- 🟢 Low: {counts_by_severity.get('low', 0)}",
            "",
            "_See metrics.json for full details._"
        ]

        (self.out / "pr_comment.md").write_text(
            "\n".join(pr_lines),
            encoding="utf-8"
        )