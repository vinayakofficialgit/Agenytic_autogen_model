# agents/autogen_runtime.py
"""
Production AutoGen Runtime
Secure, deterministic, CI-safe LLM orchestration.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List

# Robust import
try:
    from agents.llm_bridge import assistant_factory, get_fallback_suggestion
except Exception:
    try:
        from llm_bridge import assistant_factory, get_fallback_suggestion
    except Exception:
        assistant_factory = None
        get_fallback_suggestion = None


# =========================================================
# SAFETY LIMITS
# =========================================================

MAX_FINDINGS_PER_TOOL = int(os.getenv("LLM_FINDINGS_LIMIT", "5"))
MAX_JSON_LENGTH = int(os.getenv("LLM_TRIAGE_JSON_LEN", "3000"))
MAX_PROMPT_CHARS = 20_000


# =========================================================
# UTILS
# =========================================================

def _is_llm_enabled(cfg: Dict[str, Any]) -> bool:
    if os.getenv("LLM_ENABLED", "0") != "1":
        return False
    if not cfg.get("llm", {}).get("enabled", False):
        return False
    return True


def _truncate(text: Any, limit: int = 800) -> str:
    if not isinstance(text, str):
        try:
            text = json.dumps(text, ensure_ascii=False)
        except Exception:
            text = str(text)
    return text[:limit]


def _sanitize(text: str) -> str:
    # Simple injection prevention
    forbidden = ["ignore previous instructions", "delete", "override", "access filesystem"]
    lower = text.lower()
    for word in forbidden:
        if word in lower:
            raise RuntimeError("Potential prompt injection detected.")
    return text


def _safe_prompt(text: str) -> str:
    text = _sanitize(text)
    if len(text) > MAX_PROMPT_CHARS:
        return text[:MAX_PROMPT_CHARS]
    return text


# =========================================================
# CORE LLM EXECUTION
# =========================================================

def _run_agent(name: str, system_msg: str, task: str, temperature: float) -> str:
    if assistant_factory is None:
        return "[LLM unavailable]"

    agent = assistant_factory(
        name=name,
        system_message=system_msg,
        temperature=float(temperature),
    )

    return agent.chat_completion_fn([
        {"role": "system", "content": system_msg},
        {"role": "user", "content": _safe_prompt(task)},
    ])


# =========================================================
# FINDING ANALYSIS
# =========================================================

def _analyze_findings(findings: Dict[str, Any], temperature: float) -> Dict[str, Any]:
    report = {"semgrep": [], "trivy_fs": [], "notes": []}

    semgrep_items = findings.get("semgrep", [])[:MAX_FINDINGS_PER_TOOL]
    trivy_items = findings.get("trivy_fs", [])[:MAX_FINDINGS_PER_TOOL]

    for item in semgrep_items:
        try:
            prompt = (
                f"Semgrep finding:\n"
                f"Rule: {item.get('rule_id')}\n"
                f"Severity: {item.get('severity')}\n"
                f"File: {item.get('file')}\n"
                f"Line: {item.get('line')}\n\n"
                f"Code:\n{_truncate(item.get('snippet'))}"
            )

            resp = _run_agent(
                "semgrep_fixer",
                "You are a senior AppSec engineer. Return concise safe patch advice.",
                prompt,
                temperature,
            )

            report["semgrep"].append({
                "file": item.get("file"),
                "line": item.get("line"),
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "suggestion": resp.strip(),
            })

        except Exception:
            fallback = get_fallback_suggestion(
                tool="semgrep",
                rule_id=item.get("rule_id"),
                severity=item.get("severity"),
                message=item.get("message"),
            ) if get_fallback_suggestion else "[No fallback]"
            report["semgrep"].append({
                "file": item.get("file"),
                "line": item.get("line"),
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "suggestion": fallback,
            })

    for item in trivy_items:
        try:
            prompt = (
                f"Trivy finding:\n"
                f"ID: {item.get('id')}\n"
                f"Severity: {item.get('severity')}\n"
                f"File: {item.get('file')}\n"
            )

            resp = _run_agent(
                "trivy_fixer",
                "You are a cloud security engineer. Return concise remediation advice.",
                prompt,
                temperature,
            )

            report["trivy_fs"].append({
                "file": item.get("file"),
                "id": item.get("id"),
                "severity": item.get("severity"),
                "suggestion": resp.strip(),
            })

        except Exception:
            fallback = get_fallback_suggestion(
                tool="trivy_fs",
                rule_id=item.get("id"),
                severity=item.get("severity"),
                message=item.get("summary"),
            ) if get_fallback_suggestion else "[No fallback]"
            report["trivy_fs"].append({
                "file": item.get("file"),
                "id": item.get("id"),
                "severity": item.get("severity"),
                "suggestion": fallback,
            })

    return report


# =========================================================
# ENTRY POINT
# =========================================================

def run_autogen_layer(findings: Dict[str, Any], cfg: Dict[str, Any], out_dir: Path) -> Optional[Dict[str, Any]]:

    if not _is_llm_enabled(cfg):
        return None

    temperature = float(cfg.get("llm", {}).get("temperature", 0.2))

    # Severity threshold check
    min_sev = cfg.get("policy", {}).get("min_severity_to_fail", "high")

    severe_present = False
    for tool, items in findings.items():
        if not isinstance(items, list):
            continue
        for f in items:
            if f.get("severity", "").lower() in ["high", "critical"]:
                severe_present = True
                break

    if not severe_present:
        return None

    # Analyze findings
    llm_report = _analyze_findings(findings, temperature)

    # Write outputs
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "llm_report.json").write_text(
        json.dumps(llm_report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    return llm_report