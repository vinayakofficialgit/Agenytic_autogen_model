

# agents/autogen_runtime.py
"""
Enhanced AutoGen layer with quiet mode and fallback suggestions.

Output is minimal by default. Set LLM_VERBOSE=1 for debug output.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List

# Robust import
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


def _is_verbose() -> bool:
    return os.getenv("LLM_VERBOSE", "0") == "1"


def _log(msg: str):
    if _is_verbose():
        print(msg)


def _run_agent(agent_name: str, system_msg: str, task: str, temperature: float = 0.2) -> str:
    """Invoke an LLM-backed agent. Quiet by default."""
    if assistant_factory is None:
        _log(f"[autogen] LLM unavailable; returning stub for agent={agent_name}")
        return f"[LLM unavailable] {agent_name}: (stub)"

    agent = assistant_factory(name=agent_name, system_message=system_msg, temperature=temperature)
    messages = [
        {"role": "system", "content": agent.system_message},
        {"role": "user", "content": task},
    ]
    try:
        return agent.chat_completion_fn(messages)
    except Exception as e:
        _log(f"[autogen] LLM error in agent={agent_name}: {e}")
        return f"[LLM error] {agent_name}: {e}"


def _llm_banner() -> str:
    url = os.getenv("OLLAMA_URL", "(unset)")
    model = os.getenv("OLLAMA_MODEL", "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


def _truncate(txt: Any, limit: int = int(os.getenv("LLM_TRUNCATE", "800"))) -> str:
    if not isinstance(txt, str):
        try:
            txt = json.dumps(txt, ensure_ascii=False)
        except Exception:
            txt = str(txt)
    return txt if len(txt) <= limit else (txt[:limit] + "\n... [truncated] ...")


def _build_semgrep_prompt(item: Dict[str, Any]) -> str:
    return (
        "You are a senior application security engineer. "
        "Be precise, minimal, and safe. If possible, return a unified diff.\n\n"
        f"Semgrep finding (severity: {item.get('severity','')})\n"
        f"- rule_id: {item.get('rule_id','')}\n"
        f"- message: {item.get('message','')}\n"
        f"- file: {item.get('file','')}\n"
        f"- line: {item.get('line','')}\n\n"
        "Code context (may be truncated):\n"
        "```python\n"
        f"{_truncate(item.get('snippet',''))}\n"
        "```\n\n"
        "Tasks:\n"
        "1) Explain the risk in 1–2 lines.\n"
        "2) Propose a minimal unified diff for the file above.\n"
        "3) List any follow-up (tests/config)."
    )


def _build_trivy_fs_prompt(item: Dict[str, Any]) -> str:
    return (
        "You are a cloud security engineer. Prefer secure defaults and minimal changes. "
        "If applicable, return a unified diff.\n\n"
        "Trivy-FS finding:\n"
        f"- id: {item.get('id','')}\n"
        f"- severity: {item.get('severity','')}\n"
        f"- file: {item.get('file','')}\n"
        f"- summary: {item.get('summary','')}\n\n"
        "Relevant content (may be truncated):\n"
        "```\n"
        f"{_truncate(item.get('snippet',''))}\n"
        "```\n\n"
        "Tasks:\n"
        "1) Identify the insecure setting.\n"
        "2) Provide a minimal unified diff for the file (if text-based).\n"
        "3) Note any deployment/policy implications."
    )


def _get_fallback_for_semgrep(item: Dict[str, Any]) -> str:
    if get_fallback_suggestion is None:
        return "[No fallback available]"
    return get_fallback_suggestion(
        tool="semgrep",
        rule_id=item.get("rule_id", ""),
        severity=item.get("severity", ""),
        message=item.get("message", ""),
    )


def _get_fallback_for_trivy_fs(item: Dict[str, Any]) -> str:
    if get_fallback_suggestion is None:
        return "[No fallback available]"
    return get_fallback_suggestion(
        tool="trivy_fs",
        rule_id=item.get("id", ""),
        severity=item.get("severity", ""),
        message=item.get("summary", ""),
    )


def _select_grouped_findings(findings: Any) -> Dict[str, Any]:
    if isinstance(findings, dict):
        if any(k in findings for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")):
            return findings
        inner = findings.get("findings")
        if isinstance(inner, dict):
            return _select_grouped_findings(inner)
    return {}


def _analyze_findings_with_llm(findings: Dict[str, Any], temperature: float) -> Dict[str, Any]:
    """Analyze findings with LLM, using fallbacks when needed."""
    advice: Dict[str, Any] = {"semgrep": [], "trivy_fs": [], "notes": []}
    grouped = _select_grouped_findings(findings)
    if not grouped:
        advice["notes"].append("No grouped findings to analyze.")
        return advice

    sem_items = grouped.get("semgrep", []) or []
    tf_items = grouped.get("trivy_fs", []) or []
    _log(f"[autogen] Analyzing findings with LLM: semgrep={len(sem_items)} trivy_fs={len(tf_items)}")

    limit = int(os.getenv("LLM_FINDINGS_LIMIT", "5"))
    sem_slice = sem_items[:limit]
    tf_slice = tf_items[:limit]

    fallbacks_used = 0

    for item in sem_slice:
        try:
            resp = _run_agent(
                agent_name="semgrep_fixer",
                system_msg="You are a senior AppSec engineer. Produce safe, minimal patches.",
                task=_build_semgrep_prompt(item),
                temperature=temperature,
            )
            
            suggestion = (resp or "").strip()
            used_fallback = "[Fallback" in suggestion or "[LLM error]" in suggestion or "[LLM unavailable]" in suggestion
            
            if "[LLM error]" in suggestion or "[LLM unavailable]" in suggestion:
                fallback = _get_fallback_for_semgrep(item)
                if fallback:
                    suggestion = f"[Fallback - LLM unavailable]\n\n{fallback}"
                    used_fallback = True
            
            if used_fallback:
                fallbacks_used += 1
            
            advice["semgrep"].append({
                "file": item.get("file"),
                "line": item.get("line"),
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "suggestion": suggestion,
                "used_fallback": used_fallback,
            })
        except Exception as e:
            fallback = _get_fallback_for_semgrep(item)
            advice["semgrep"].append({
                "file": item.get("file"),
                "line": item.get("line"),
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "suggestion": f"[Fallback - Error]\n\n{fallback}" if fallback else f"[Error: {e}]",
                "used_fallback": True,
            })
            fallbacks_used += 1

    for item in tf_slice:
        try:
            resp = _run_agent(
                agent_name="trivy_fs_fixer",
                system_msg="You are a cloud security engineer. Suggest secure config changes.",
                task=_build_trivy_fs_prompt(item),
                temperature=temperature,
            )
            
            suggestion = (resp or "").strip()
            used_fallback = "[Fallback" in suggestion or "[LLM error]" in suggestion or "[LLM unavailable]" in suggestion
            
            if "[LLM error]" in suggestion or "[LLM unavailable]" in suggestion:
                fallback = _get_fallback_for_trivy_fs(item)
                if fallback:
                    suggestion = f"[Fallback - LLM unavailable]\n\n{fallback}"
                    used_fallback = True
            
            if used_fallback:
                fallbacks_used += 1
            
            advice["trivy_fs"].append({
                "file": item.get("file"),
                "id": item.get("id"),
                "severity": item.get("severity"),
                "suggestion": suggestion,
                "used_fallback": used_fallback,
            })
        except Exception as e:
            fallback = _get_fallback_for_trivy_fs(item)
            advice["trivy_fs"].append({
                "file": item.get("file"),
                "id": item.get("id"),
                "severity": item.get("severity"),
                "suggestion": f"[Fallback - Error]\n\n{fallback}" if fallback else f"[Error: {e}]",
                "used_fallback": True,
            })
            fallbacks_used += 1

    if len(sem_items) > len(sem_slice) or len(tf_items) > len(tf_slice):
        advice["notes"].append(f"Analysis limited to first {limit} items per tool.")

    if fallbacks_used > 0:
        advice["notes"].append(f"Used {fallbacks_used} fallback suggestion(s) - LLM was unavailable.")

    return advice


def run_autogen_layer(findings: Dict[str, Any], cfg: Dict[str, Any], out_dir: Path) -> Optional[Dict[str, Any]]:
    """
    Entry point for the AutoGen layer.
    
    Returns LLM report with suggestions for each finding.
    Output is quiet by default - set LLM_VERBOSE=1 for debug output.
    """
    llm_enabled_cfg = bool(cfg.get("llm", {}).get("enabled", False))
    llm_enabled_env = os.getenv("LLM_ENABLED", "").strip() == "1"
    ollama_present = bool(os.getenv("OLLAMA_URL"))
    llm_enabled = llm_enabled_cfg or llm_enabled_env or ollama_present
    
    _log(f"[autogen] LLM enabled? cfg={llm_enabled_cfg} env={llm_enabled_env} -> effective={llm_enabled}")
    
    if not llm_enabled:
        return None

    temperature = float(cfg.get("llm", {}).get("temperature", 0.2))

    # Health check (quiet)
    if check_ollama_health:
        health = check_ollama_health()
        if health["healthy"]:
            _log(f"[autogen] ✓ Ollama healthy: model={health['model_name']}")
        else:
            _log(f"[autogen] ⚠ Ollama not healthy: {health.get('error')}")

    # Warmup (quiet)
    try:
        _ = _run_agent("warmup", "You are a helpful assistant.", "Reply with READY.", temperature=0.0)
        _log("[autogen] Warmup call done.")
    except Exception as e:
        _log(f"[autogen] Warmup skipped: {e}")

    # Triage (quiet)
    max_triage = int(os.getenv("LLM_TRIAGE_JSON_LEN", "2000"))
    triage_task = (
        "You are a senior AppSec triage engineer. Given the following merged findings JSON, "
        "cluster the issues by root cause (code/infra/image/policy), rank by risk and blast radius, "
        "and produce a concise ordered list of what to fix first. Keep it under 12 bullets.\n\n"
        + json.dumps(findings, ensure_ascii=False)[:max_triage]
    )
    triage_msg = _run_agent(
        "triage",
        "Act as an expert AppSec triage engineer. Be concise and prioritize effectively.",
        triage_task,
        temperature,
    )

    # Policy Advisor (quiet)
    min_sev = cfg.get("policy", {}).get("min_severity_to_fail", "high")
    advisor_task = (
        f"We gate on min severity = {min_sev}. "
        "Explain how OPA/Conftest policy violations should influence the decision. "
        "Draft a short policy note for the PR reviewers (under 8 bullets)."
    )
    advisor_msg = _run_agent(
        "policy_advisor",
        "Act as a policy advisor for AppSec and platform guardrails. Be crisp and actionable.",
        advisor_task,
        temperature,
    )

    # Reporter (quiet)
    report_task = (
        "Compose an executive summary for the PR body that includes: "
        "(1) top risks & priorities, "
        "(2) what the auto-remediation will change (Dockerfile/K8s/TF), and "
        "(3) next steps. Keep under 200 words.\n\n"
        f"Triage notes:\n{triage_msg}\n\nPolicy notes:\n{advisor_msg}"
    )
    report_msg = _run_agent(
        "reporter",
        "You write crisp executive summaries for engineering leadership.",
        report_task,
        temperature,
    )

    # Per-finding analysis
    llm_report = _analyze_findings_with_llm(findings=findings, temperature=temperature)

    # Write outputs
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Agentic summary
    out_path = out_dir / "agentic_summary.md"
    out_path.write_text(
        _llm_banner()
        + "# Agentic Summary (AutoGen)\n\n"
        + f"## Triage\n{triage_msg}\n\n"
        + f"## Policy\n{advisor_msg}\n\n"
        + f"## PR Summary\n{report_msg}\n\n"
        + "## LLM Recommendations (Per Finding)\n"
        + "- See `llm_recommendations.md` for full details.\n",
        encoding="utf-8",
    )

    # LLM recommendations markdown
    rec_path = out_dir / "llm_recommendations.md"
    md: List[str] = [_llm_banner(), "# LLM Recommendations (Per Finding)\n"]
    
    fallback_count = sum(1 for item in llm_report.get("semgrep", []) if item.get("used_fallback"))
    fallback_count += sum(1 for item in llm_report.get("trivy_fs", []) if item.get("used_fallback"))
    
    if fallback_count > 0:
        md.append(f"> ⚠️ **Note**: {fallback_count} suggestion(s) used built-in security knowledge (LLM unavailable).\n\n")
    
    if llm_report.get("semgrep"):
        md.append("## Semgrep\n")
        for item in llm_report["semgrep"]:
            sev = str(item.get('severity', '')).upper()
            fallback_marker = " 🔄" if item.get("used_fallback") else ""
            md.append(f"### {sev}{fallback_marker} – {item.get('file')}:{item.get('line')} ({item.get('rule_id')})\n")
            md.append(f"{(item.get('suggestion') or '').strip()}\n")
    
    if llm_report.get("trivy_fs"):
        md.append("## Trivy-FS\n")
        for item in llm_report["trivy_fs"]:
            sev = str(item.get('severity', '')).upper()
            fallback_marker = " 🔄" if item.get("used_fallback") else ""
            md.append(f"### {sev}{fallback_marker} – {item.get('file')} ({item.get('id')})\n")
            md.append(f"{(item.get('suggestion') or '').strip()}\n")
    
    if llm_report.get("notes"):
        md.append("## Notes\n")
        for note in llm_report["notes"]:
            md.append(f"- {note}\n")
    
    rec_path.write_text("\n".join(md), encoding="utf-8")

    # JSON report
    (out_dir / "llm_report.json").write_text(
        json.dumps(llm_report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    
    _log(f"[autogen] Wrote: {out_path}, {rec_path}, {out_dir / 'llm_report.json'}")
    _log(f"[autogen] Returning llm_report: semgrep={len(llm_report.get('semgrep', []))} trivy_fs={len(llm_report.get('trivy_fs', []))}")
    
    if fallback_count > 0:
        _log(f"[autogen] ⚠ Used fallback suggestions for {fallback_count} finding(s)")

    return llm_report