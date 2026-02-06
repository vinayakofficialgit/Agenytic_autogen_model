

# # reporter.py

# from __future__ import annotations
# from pathlib import Path
# from typing import Dict, Any, List, Optional
# import json
# import os


# class Reporter:
#     """
#     Reporter produces:
#       - metrics.json           (counts per source, status, totals)
#       - (optional) metrics_explained.md  if LLM_EXPLAIN=1 and llm_bridge.py available
#     """

#     def __init__(self, config: Dict[str, Any], output_dir: Path):
#         self.cfg = config or {}
#         self.out = Path(output_dir)

#     # ---------------------------------------------------------
#     # Optional LLM-based explanation (Ollama via llm_bridge.py)
#     # ---------------------------------------------------------
#     def _maybe_llm_explain(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Generates a short natural-language summary IF:
#             - LLM_EXPLAIN=1 is exported in the environment
#             - llm_bridge.py is available (assistant_factory import succeeds)
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             return None

#         # Robust import: try agents.llm_bridge first, then llm_bridge at repo root
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 return None

#         # Lightweight summary of findings by source/tool
#         src_counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "unknown")
#             src_counts[src] = src_counts.get(src, 0) + 1

#         system_msg = (
#             "You are a DevSecOps assistant. "
#             "Explain these metrics clearly for a pull request summary. "
#             "Be concise, factual, and avoid hallucinations."
#         )

#         user_msg = (
#             "Here are the aggregated findings metrics and gate decision.\n\n"
#             f"Counts by source:\n{json.dumps(src_counts, indent=2)}\n\n"
#             f"Decision:\n{json.dumps(decision, indent=2)}\n\n"
#             "Write a short summary (<= 200 words)."
#         )

#         agent = assistant_factory(
#             name="reporter_llm",
#             system_message=system_msg,
#             temperature=0.2,
#         )

#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user",    "content": user_msg},
#         ]

#         try:
#             explanation = agent.chat_completion_fn(messages)
#             if explanation:
#                 md_path = self.out / "metrics_explained.md"
#                 md_path.write_text(explanation, encoding="utf-8")
#                 return str(md_path)
#         except Exception:
#             return None

#         return None

#     # ---------------------------------------------------------
#     # Optional LLM: Agent capability & best-practices guidance
#     # ---------------------------------------------------------
#     def _maybe_llm_guidance(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Produces agent_output/agent_guidance.md with:
#           - Warnings when high/critical exist
#           - Tool-specific best practices (Semgrep, Trivy, tfsec, ZAP, Gitleaks)
#           - Suggestions to improve agent capabilities (prompts, thresholds, caching, parallelism)
#         Runs only when LLM_EXPLAIN=1 and llm_bridge is available.
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             return None

#         # Robust import
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 return None

#         # Summaries for prompt
#         by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#         by_tool: Dict[str, int] = {}
#         for f in findings:
#             sev = (f.get("severity") or "low").lower()
#             by_sev[sev] = by_sev.get(sev, 0) + 1
#             t = (f.get("tool") or f.get("source") or "unknown")
#             by_tool[t] = by_tool.get(t, 0) + 1

#         # Determine worst severity present
#         worst = next((s for s in ["critical", "high", "medium", "low"] if by_sev.get(s, 0) > 0), "low")

#         system_msg = (
#             "You are a senior DevSecOps mentor for CI/CD agents. "
#             "Review the scan outcome and provide:\n"
#             "1) Key warnings (if high/critical present).\n"
#             "2) Concrete suggestions to improve agent capabilities (config, prompts, thresholds, caching, parallelism).\n"
#             "3) Best practices per tool (Semgrep, Trivy, tfsec, ZAP, Gitleaks) with short examples.\n"
#             "Be concise, practical, and only use provided data. Output in markdown with headings and bullet points."
#         )

#         user_msg = (
#             f"Worst severity: {worst}\n"
#             f"By severity: {json.dumps(by_sev, indent=2)}\n"
#             f"By tool: {json.dumps(by_tool, indent=2)}\n"
#             f"Gate decision: {json.dumps(decision, indent=2)}\n"
#             "Sample findings:\n" + json.dumps(findings[:5], indent=2)
#         )

#         agent = assistant_factory(
#             name="agent_guidance",
#             system_message=system_msg,
#             temperature=0.2
#         )
#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user", "content": user_msg},
#         ]
#         try:
#             md = agent.chat_completion_fn(messages)
#             if md:
#                 outp = self.out / "agent_guidance.md"
#                 outp.write_text(md, encoding="utf-8")
#                 return str(outp)
#         except Exception:
#             return None
#         return None

#     # ---------------------------------------------------------
#     # Main writer: metrics.json + optional LLM summary
#     # ---------------------------------------------------------
#     def emit(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]):
#         """
#         Writes:
#         - metrics.json
#         - optionally metrics_explained.md (if LLM_EXPLAIN=1)
#         - optionally agent_guidance.md (if LLM_EXPLAIN=1)
#         """
#         self.out.mkdir(parents=True, exist_ok=True)

#         # Count findings by source
#         counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "other")
#             counts[src] = counts.get(src, 0) + 1

#         # Build metrics object
#         metrics = {
#             "counts": counts,
#             "total_findings": sum(counts.values()),
#             "gate_status": decision.get("status"),
#             "reason": decision.get("reason"),
#             # Backwards compatibility: include fail_count if derived
#             "fail_count": 1 if decision.get("status") == "fail" else 0,
#         }

#         # Write metrics.json
#         (self.out / "metrics.json").write_text(
#             json.dumps(metrics, indent=2),
#             encoding="utf-8"
#         )

#         # Optional LLM explanation
#         self._maybe_llm_explain(findings, decision)

#         # Optional LLM agent capability / best-practices guidance
#         self._maybe_llm_guidance(findings, decision)



##########################################################################




# #imp

# # reporter.py

# from __future__ import annotations
# from pathlib import Path
# from typing import Dict, Any, List, Optional
# import json
# import os


# class Reporter:
#     """
#     Reporter produces:
#       - metrics.json           (counts per source, status, totals)
#       - (optional) metrics_explained.md  if LLM_EXPLAIN=1 and llm_bridge.py available
#     """

#     def __init__(self, config: Dict[str, Any], output_dir: Path):
#         self.cfg = config or {}
#         self.out = Path(output_dir)

#     # ---------------------------------------------------------
#     # Optional LLM-based explanation (Ollama via llm_bridge.py)
#     # ---------------------------------------------------------
#     def _maybe_llm_explain(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Generates a short natural-language summary IF:
#             - LLM_EXPLAIN=1 is exported in the environment
#             - llm_bridge.py is available (assistant_factory import succeeds)
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             return None

#         # Robust import: try agents.llm_bridge first, then llm_bridge at repo root
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 return None

#         # Lightweight summary of findings by source/tool
#         src_counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "unknown")
#             src_counts[src] = src_counts.get(src, 0) + 1

#         system_msg = (
#             "You are a DevSecOps assistant. "
#             "Explain these metrics clearly for a pull request summary. "
#             "Be concise, factual, and avoid hallucinations."
#         )

#         user_msg = (
#             "Here are the aggregated findings metrics and gate decision.\n\n"
#             f"Counts by source:\n{json.dumps(src_counts, indent=2)}\n\n"
#             f"Decision:\n{json.dumps(decision, indent=2)}\n\n"
#             "Write a short summary (<= 200 words)."
#         )

#         agent = assistant_factory(
#             name="reporter_llm",
#             system_message=system_msg,
#             temperature=0.2,
#         )

#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user",    "content": user_msg},
#         ]

#         try:
#             explanation = agent.chat_completion_fn(messages)
#             if explanation:
#                 md_path = self.out / "metrics_explained.md"
#                 md_path.write_text(explanation, encoding="utf-8")
#                 return str(md_path)
#         except Exception:
#             return None

#         return None

#     # ---------------------------------------------------------
#     # Optional LLM: Agent capability & best-practices guidance
#     # ---------------------------------------------------------
#     def _maybe_llm_guidance(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Produces agent_output/agent_guidance.md with:
#           - Warnings when high/critical exist
#           - Tool-specific best practices (Semgrep, Trivy, tfsec, ZAP, Gitleaks)
#           - Suggestions to improve agent capabilities (prompts, thresholds, caching, parallelism)
#         Runs only when LLM_EXPLAIN=1 and llm_bridge is available.
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             return None

#         # Robust import
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 return None

#         # Summaries for prompt
#         by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#         by_tool: Dict[str, int] = {}
#         for f in findings:
#             sev = (f.get("severity") or "low").lower()
#             by_sev[sev] = by_sev.get(sev, 0) + 1
#             t = (f.get("tool") or f.get("source") or "unknown")
#             by_tool[t] = by_tool.get(t, 0) + 1

#         # Determine worst severity present
#         worst = next((s for s in ["critical", "high", "medium", "low"] if by_sev.get(s, 0) > 0), "low")

#         system_msg = (
#             "You are a senior DevSecOps mentor for CI/CD agents. "
#             "Review the scan outcome and provide:\n"
#             "1) Key warnings (if high/critical present).\n"
#             "2) Concrete suggestions to improve agent capabilities (config, prompts, thresholds, caching, parallelism).\n"
#             "3) Best practices per tool (Semgrep, Trivy, tfsec, ZAP, Gitleaks) with short examples.\n"
#             "Be concise, practical, and only use provided data. Output in markdown with headings and bullet points."
#         )

#         user_msg = (
#             f"Worst severity: {worst}\n"
#             f"By severity: {json.dumps(by_sev, indent=2)}\n"
#             f"By tool: {json.dumps(by_tool, indent=2)}\n"
#             f"Gate decision: {json.dumps(decision, indent=2)}\n"
#             "Sample findings:\n" + json.dumps(findings[:5], indent=2)
#         )

#         agent = assistant_factory(
#             name="agent_guidance",
#             system_message=system_msg,
#             temperature=0.2
#         )
#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user", "content": user_msg},
#         ]
#         try:
#             md = agent.chat_completion_fn(messages)
#             if md:
#                 outp = self.out / "agent_guidance.md"
#                 outp.write_text(md, encoding="utf-8")
#                 return str(outp)
#         except Exception:
#             return None
#         return None

#     # ---------------------------------------------------------
#     # Main writer: metrics.json + optional LLM summary
#     # ---------------------------------------------------------
#     def emit(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]):
#         """
#         Writes:
#         - metrics.json
#         - optionally metrics_explained.md (if LLM_EXPLAIN=1)
#         - optionally agent_guidance.md (if LLM_EXPLAIN=1)
#         """
#         self.out.mkdir(parents=True, exist_ok=True)

#         # Count findings by source
#         counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "other")
#             counts[src] = counts.get(src, 0) + 1

#         # Build metrics object
#         metrics = {
#             "counts": counts,
#             "total_findings": sum(counts.values()),
#             "gate_status": decision.get("status"),
#             "reason": decision.get("reason"),
#             # Backwards compatibility: include fail_count if derived
#             "fail_count": 1 if decision.get("status") == "fail" else 0,
#         }

#         # Write metrics.json
#         (self.out / "metrics.json").write_text(
#             json.dumps(metrics, indent=2),
#             encoding="utf-8"
#         )

#         # Optional LLM explanation
#         self._maybe_llm_explain(findings, decision)

#         # Optional LLM agent capability / best-practices guidance
#         self._maybe_llm_guidance(findings, decision)










####################
# reporter.py
"""
Enhanced Reporter for DevSecOps Agentic AI Pipeline

Produces:
  - metrics.json (counts & gate status)
  - metrics_explained.md (optional, if LLM_EXPLAIN=1)
  - agent_guidance.md (optional, if LLM_EXPLAIN=1)
  - llm_recommendations_summary.md (if Decision contains LLM report)
  - pr_comment.md (concise PR summary with LLM suggestions)

Key Enhancements:
- Better LLM integration with fallback support
- Improved formatting and readability
- More detailed metrics and summaries
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import json
import os


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


class Reporter:
    """
    Reporter produces various output artifacts for the DevSecOps pipeline.
    """

    def __init__(self, config: Dict[str, Any], output_dir: Path):
        self.cfg = config or {}
        self.out = Path(output_dir)

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------
    def _flatten_for_counts(self, findings_input: Union[List[Dict[str, Any]], Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flatten grouped findings dict to list for counting."""
        if isinstance(findings_input, list):
            return [f for f in findings_input if isinstance(f, dict)]
        if isinstance(findings_input, dict):
            flat: List[Dict[str, Any]] = []
            for k, v in findings_input.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, list):
                    flat.extend([f for f in v if isinstance(f, dict)])
            return flat
        return []

    def _counts_by(self, findings_flat: List[Dict[str, Any]], key: str, fallback_key: Optional[str] = None) -> Dict[str, int]:
        """Count findings by a specific key."""
        out: Dict[str, int] = {}
        for f in findings_flat:
            if not isinstance(f, dict):
                continue
            val = f.get(key) or (f.get(fallback_key) if fallback_key else None) or "other"
            out[val] = out.get(val, 0) + 1
        return out

    @staticmethod
    def _llm_banner() -> str:
        """Small banner showing LLM configuration."""
        url = os.getenv("OLLAMA_URL", "(unset)")
        model = os.getenv("OLLAMA_MODEL", "(unset)")
        mode = os.getenv("LLM_MODE", "ollama")
        return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"

    def _llm_ask(self, name: str, system: str, user: str, temperature: float = 0.2) -> Optional[str]:
        """Ask the LLM for a response."""
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
            print(f"[reporter] LLM error: {e}")
            return None

    # ---------------------------------------------------------
    # LLM-based explanation
    # ---------------------------------------------------------
    def _maybe_llm_explain(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
        """Generate LLM explanation of metrics if LLM_EXPLAIN=1."""
        if os.getenv("LLM_EXPLAIN", "").strip() != "1":
            return None

        # Summary by source/tool
        src_counts: Dict[str, int] = {}
        for f in findings:
            src = f.get("source", f.get("tool", "unknown"))
            src_counts[src] = src_counts.get(src, 0) + 1

        system_msg = (
            "You are a DevSecOps assistant. "
            "Explain these metrics clearly for a pull request summary. "
            "Be concise, factual, and avoid hallucinations."
        )

        user_msg = (
            "Here are the aggregated findings metrics and gate decision.\n\n"
            f"Counts by source/tool:\n{json.dumps(src_counts, indent=2)}\n\n"
            f"Decision:\n{json.dumps(decision, indent=2)}\n\n"
            "Write a short summary (<= 200 words) explaining the security posture."
        )

        explanation = self._llm_ask("reporter_llm", system_msg, user_msg, temperature=0.2)
        
        if explanation:
            self.out.mkdir(parents=True, exist_ok=True)
            md_path = self.out / "metrics_explained.md"
            try:
                content = self._llm_banner()
                if "[Fallback" in explanation:
                    content += "> ⚠️ Note: Using fallback explanation (LLM unavailable)\n\n"
                content += explanation.strip()
                md_path.write_text(content, encoding="utf-8")
                return str(md_path)
            except Exception as e:
                print(f"[reporter] Error writing explanation: {e}")
        
        return None

    # ---------------------------------------------------------
    # LLM: Agent guidance
    # ---------------------------------------------------------
    def _maybe_llm_guidance(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
        """Generate agent guidance document if LLM_EXPLAIN=1."""
        if os.getenv("LLM_EXPLAIN", "").strip() != "1":
            return None

        # Summaries for prompt
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_tool: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            t = f.get("tool") or f.get("source") or "unknown"
            by_tool[t] = by_tool.get(t, 0) + 1

        worst = next((s for s in ["critical", "high", "medium", "low"] if by_sev.get(s, 0) > 0), "low")

        system_msg = (
            "You are a senior DevSecOps mentor for CI/CD agents. "
            "Review the scan outcome and provide:\n"
            "1) Key warnings (if high/critical present).\n"
            "2) Concrete suggestions to improve agent capabilities.\n"
            "3) Best practices per tool (Semgrep, Trivy, tfsec, ZAP, Gitleaks).\n"
            "Be concise, practical, and use markdown with headings and bullet points."
        )

        user_msg = (
            f"Worst severity: {worst}\n"
            f"By severity: {json.dumps(by_sev, indent=2)}\n"
            f"By tool: {json.dumps(by_tool, indent=2)}\n"
            f"Gate decision: {json.dumps(decision, indent=2)}\n"
            f"Sample findings:\n{json.dumps(findings[:5], indent=2)}"
        )

        guidance = self._llm_ask("agent_guidance", system_msg, user_msg, temperature=0.2)
        
        if guidance:
            self.out.mkdir(parents=True, exist_ok=True)
            outp = self.out / "agent_guidance.md"
            try:
                content = self._llm_banner()
                if "[Fallback" in guidance:
                    content += "> ⚠️ Note: Using fallback guidance (LLM unavailable)\n\n"
                content += guidance.strip()
                outp.write_text(content, encoding="utf-8")
                return str(outp)
            except Exception as e:
                print(f"[reporter] Error writing guidance: {e}")
        
        return None

    # ---------------------------------------------------------
    # LLM Recommendations from Decision
    # ---------------------------------------------------------
    def _load_llm_report_from_decision(self, decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Load LLM report from decision or file."""
        rem = decision.get("remediation") or {}
        
        # Try inline data first
        data = rem.get("llm_report")
        if isinstance(data, dict):
            return data
        
        # Try path
        path = rem.get("llm_report_path")
        if isinstance(path, str) and path.strip():
            p = Path(path)
            if p.exists():
                try:
                    return json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    pass
        
        # Try default path
        default_path = self.out / "llm_report.json"
        if default_path.exists():
            try:
                return json.loads(default_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        
        return None

    def _truncate(self, text: str, limit: int) -> str:
        """Truncate text to limit."""
        if not isinstance(text, str):
            try:
                text = json.dumps(text, ensure_ascii=False)
            except Exception:
                text = str(text)
        return text if len(text) <= limit else (text[:limit] + "\n... [truncated] ...")

    def _emit_llm_recommendations(self, decision: Dict[str, Any]) -> List[str]:
        """Generate LLM recommendations summary and PR comment."""
        llm_report = self._load_llm_report_from_decision(decision)
        if not llm_report:
            return []

        written: List[str] = []
        max_items = int(os.getenv("MAX_LLM_ITEMS_PER_GROUP", "5"))
        max_chars = int(os.getenv("MAX_LLM_SUGGESTION_CHARS", "2000"))

        # Build summary markdown
        lines: List[str] = [self._llm_banner(), "# LLM Recommendations Summary\n"]
        
        # Count fallbacks
        fallback_count = sum(
            1 for item in llm_report.get("semgrep", []) if item.get("used_fallback")
        ) + sum(
            1 for item in llm_report.get("trivy_fs", []) if item.get("used_fallback")
        )
        
        if fallback_count > 0:
            lines.append(f"> ⚠️ **Note**: {fallback_count} suggestion(s) are fallback recommendations (LLM unavailable).\n")
            lines.append("> For AI-powered suggestions, ensure Ollama is running.\n\n")

        # Semgrep section
        sem_list = llm_report.get("semgrep") or []
        if sem_list:
            lines.append("## Semgrep Findings\n")
            for item in sem_list[:max_items]:
                sev = (item.get('severity') or '').upper()
                sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
                fallback = " 🔄" if item.get("used_fallback") else ""
                title = f"### {sev_icon} **{sev}**{fallback} – `{item.get('file')}:{item.get('line')}` ({item.get('rule_id')})\n"
                lines.append(title)
                suggestion = self._truncate((item.get("suggestion") or "").strip(), max_chars)
                lines.append(suggestion + "\n")

        # Trivy-FS section
        tf_list = llm_report.get("trivy_fs") or []
        if tf_list:
            lines.append("## Trivy-FS Findings\n")
            for item in tf_list[:max_items]:
                sev = (item.get('severity') or '').upper()
                sev_icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🟢"
                fallback = " 🔄" if item.get("used_fallback") else ""
                title = f"### {sev_icon} **{sev}**{fallback} – `{item.get('file')}` ({item.get('id')})\n"
                lines.append(title)
                suggestion = self._truncate((item.get("suggestion") or "").strip(), max_chars)
                lines.append(suggestion + "\n")

        # Notes
        notes = llm_report.get("notes") or []
        if notes:
            lines.append("## Notes\n")
            for n in notes[:max_items]:
                lines.append(f"- {n}\n")

        # Write summary
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            summary_md = self.out / "llm_recommendations_summary.md"
            summary_md.write_text("\n".join(lines), encoding="utf-8")
            written.append(str(summary_md))
        except Exception as e:
            print(f"[reporter] Error writing recommendations: {e}")

        # Build PR comment
        pr_lines: List[str] = []
        status = decision.get("status", "ok")
        reason = decision.get("reason", "")
        stats = decision.get("stats", {})
        
        status_icon = "❌" if status == "fail" else "✅"
        pr_lines.append(f"## 🛡️ Security Scan — {status_icon} {'Fail' if status=='fail' else 'Pass'}")
        pr_lines.append("")
        
        if reason:
            pr_lines.append(f"**Reason:** {reason}")
            pr_lines.append("")
        
        # Quick stats
        if stats:
            pr_lines.append("### Summary")
            pr_lines.append(f"- **Total findings:** {stats.get('total', 0)}")
            pr_lines.append(f"- **Worst severity:** {stats.get('worst_severity', 'low')}")
            by_sev = stats.get("by_severity", {})
            pr_lines.append(f"- 🔴 Critical: {by_sev.get('critical', 0)} | 🟠 High: {by_sev.get('high', 0)} | 🟡 Medium: {by_sev.get('medium', 0)} | 🟢 Low: {by_sev.get('low', 0)}")
            pr_lines.append("")
        
        # Top suggestions
        pr_lines.append("### Top Recommendations")
        
        if sem_list:
            pr_lines.append("\n**Semgrep:**")
            for item in sem_list[:3]:
                sev = (item.get('severity') or '').upper()
                fallback = " 🔄" if item.get("used_fallback") else ""
                pr_lines.append(f"- [{sev}]{fallback} `{item.get('file')}:{item.get('line')}` ({item.get('rule_id')})")
        
        if tf_list:
            pr_lines.append("\n**Trivy-FS:**")
            for item in tf_list[:3]:
                sev = (item.get('severity') or '').upper()
                fallback = " 🔄" if item.get("used_fallback") else ""
                pr_lines.append(f"- [{sev}]{fallback} `{item.get('file')}` ({item.get('id')})")
        
        pr_lines.append("")
        pr_lines.append("---")
        pr_lines.append("_See `llm_recommendations_summary.md` for full details._")
        
        if fallback_count > 0:
            pr_lines.append(f"\n_🔄 = Fallback suggestion ({fallback_count} total) - LLM was unavailable_")

        try:
            pr_md = self.out / "pr_comment.md"
            pr_md.write_text("\n".join(pr_lines), encoding="utf-8")
            written.append(str(pr_md))
        except Exception as e:
            print(f"[reporter] Error writing PR comment: {e}")

        return written

    # ---------------------------------------------------------
    # Main writer
    # ---------------------------------------------------------
    def emit(self, findings_input: Union[List[Dict[str, Any]], Dict[str, Any]], decision: Dict[str, Any]):
        """
        Write all reporter artifacts.
        
        - metrics.json
        - metrics_explained.md (if LLM_EXPLAIN=1)
        - agent_guidance.md (if LLM_EXPLAIN=1)
        - llm_recommendations_summary.md (if LLM report present)
        - pr_comment.md (if LLM report present)
        """
        self.out.mkdir(parents=True, exist_ok=True)
        print("[reporter] Generating artifacts...")

        # Normalize input
        findings = self._flatten_for_counts(findings_input)

        # Counts
        counts_by_tool = self._counts_by(findings, "tool", fallback_key="source")
        counts_by_source = self._counts_by(findings, "source", fallback_key="tool")
        counts_by_severity = self._counts_by(findings, "severity")

        # Build metrics
        metrics = {
            "counts": counts_by_source,
            "counts_by_source": counts_by_source,
            "counts_by_tool": counts_by_tool,
            "counts_by_severity": counts_by_severity,
            "total_findings": len(findings),
            "gate_status": decision.get("status"),
            "reason": decision.get("reason"),
            "fail_count": 1 if decision.get("status") == "fail" else 0,
            "stats": decision.get("stats", {}),
        }

        # Write metrics.json
        try:
            (self.out / "metrics.json").write_text(
                json.dumps(metrics, indent=2),
                encoding="utf-8"
            )
            print("[reporter] Wrote metrics.json")
        except Exception as e:
            print(f"[reporter] Error writing metrics.json: {e}")

        # Optional LLM explanation
        if self._maybe_llm_explain(findings, decision):
            print("[reporter] Wrote metrics_explained.md")

        # Optional LLM guidance
        if self._maybe_llm_guidance(findings, decision):
            print("[reporter] Wrote agent_guidance.md")

        # LLM recommendations (if present)
        rec_files = self._emit_llm_recommendations(decision)
        if rec_files:
            print(f"[reporter] Wrote {len(rec_files)} recommendation file(s)")

        print("[reporter] Done.")



##########################




# # agents/reporter.py

# from __future__ import annotations
# from pathlib import Path
# from typing import Dict, Any, List, Optional
# import json
# import os


# class Reporter:
#     """
#     Reporter produces:
#       - metrics.json           (counts per source, status, totals)
#       - (optional) metrics_explained.md  if LLM_EXPLAIN=1 and llm_bridge.py available
#     """

#     def __init__(self, config: Dict[str, Any], output_dir: Path):
#         self.cfg = config or {}
#         self.out = Path(output_dir)

#     # ---------------------------------------------------------
#     # Optional LLM-based explanation (Ollama via llm_bridge.py)
#     # ---------------------------------------------------------
#     def _maybe_llm_explain(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Generates a short natural-language summary IF:
#             - LLM_EXPLAIN=1 is exported in the environment
#             - llm_bridge.py is available (assistant_factory import succeeds)
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             print("[reporter] LLM_EXPLAIN != 1; skipping metrics_explained.md")
#             return None

#         # Robust import: try agents.llm_bridge first, then llm_bridge at repo root
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 print("[reporter] assistant_factory import failed; skipping metrics_explained.md")
#                 return None

#         # Lightweight summary of findings by source/tool
#         src_counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "unknown")
#             src_counts[src] = src_counts.get(src, 0) + 1

#         system_msg = (
#             "You are a DevSecOps assistant. "
#             "Explain these metrics clearly for a pull request summary. "
#             "Be concise, factual, and avoid hallucinations."
#         )

#         user_msg = (
#             "Here are the aggregated findings metrics and gate decision.\n\n"
#             f"Counts by source:\n{json.dumps(src_counts, indent=2)}\n\n"
#             f"Decision:\n{json.dumps(decision, indent=2)}\n\n"
#             "Write a short summary (<= 200 words)."
#         )

#         agent = assistant_factory(
#             name="reporter_llm",
#             system_message=system_msg,
#             temperature=0.2,
#         )

#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user",    "content": user_msg},
#         ]

#         md_path = self.out / "metrics_explained.md"
#         try:
#             explanation = agent.chat_completion_fn(messages) or ""
#             if not explanation.strip():
#                 explanation = (
#                     "*(No model content returned. This may happen if the model is loading or timed out.)*\n\n"
#                     "Counts by source:\n"
#                     f"{json.dumps(src_counts, indent=2)}\n\n"
#                     "Decision:\n"
#                     f"{json.dumps(decision, indent=2)}\n"
#                 )
#                 print("[reporter] LLM returned empty; writing fallback metrics_explained.md")
#             md_path.write_text(explanation, encoding="utf-8")
#             print(f"[reporter] Wrote {md_path}")
#             return str(md_path)
#         except Exception as e:
#             print(f"[reporter] LLM explain error: {e}; writing fallback metrics_explained.md")
#             fallback = (
#                 "*(LLM error while generating explanation; fallback written.)*\n\n"
#                 "Counts by source:\n"
#                 f"{json.dumps(src_counts, indent=2)}\n\n"
#                 "Decision:\n"
#                 f"{json.dumps(decision, indent=2)}\n"
#             )
#             md_path.write_text(fallback, encoding="utf-8")
#             return str(md_path)

#     # ---------------------------------------------------------
#     # Optional LLM: Agent capability & best-practices guidance
#     # ---------------------------------------------------------
#     def _maybe_llm_guidance(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]) -> Optional[str]:
#         """
#         Produces agent_output/agent_guidance.md with:
#           - Warnings when high/critical exist
#           - Tool-specific best practices (Semgrep, Trivy, tfsec, ZAP, Gitleaks)
#           - Suggestions to improve agent capabilities (prompts, thresholds, caching, parallelism)
#         Runs only when LLM_EXPLAIN=1 and llm_bridge is available.
#         """
#         if os.getenv("LLM_EXPLAIN", "").strip() != "1":
#             print("[reporter] LLM_EXPLAIN != 1; skipping agent_guidance.md")
#             return None

#         # Robust import
#         try:
#             from agents.llm_bridge import assistant_factory  # type: ignore
#         except Exception:
#             try:
#                 from llm_bridge import assistant_factory  # type: ignore
#             except Exception:
#                 print("[reporter] assistant_factory import failed; skipping agent_guidance.md")
#                 return None

#         # Summaries for prompt
#         by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#         by_tool: Dict[str, int] = {}
#         for f in findings:
#             sev = (f.get("severity") or "low").lower()
#             by_sev[sev] = by_sev.get(sev, 0) + 1
#             t = (f.get("tool") or f.get("source") or "unknown")
#             by_tool[t] = by_tool.get(t, 0) + 1

#         # Determine worst severity present
#         worst = next((s for s in ["critical", "high", "medium", "low"] if by_sev.get(s, 0) > 0), "low")

#         system_msg = (
#             "You are a senior DevSecOps mentor for CI/CD agents. "
#             "Review the scan outcome and provide:\n"
#             "1) Key warnings (if high/critical present).\n"
#             "2) Concrete suggestions to improve agent capabilities (config, prompts, thresholds, caching, parallelism).\n"
#             "3) Best practices per tool (Semgrep, Trivy, tfsec, ZAP, Gitleaks) with short examples.\n"
#             "Be concise, practical, and only use provided data. Output in markdown with headings and bullet points."
#         )

#         user_msg = (
#             f"Worst severity: {worst}\n"
#             f"By severity: {json.dumps(by_sev, indent=2)}\n"
#             f"By tool: {json.dumps(by_tool, indent=2)}\n"
#             f"Gate decision: {json.dumps(decision, indent=2)}\n"
#             "Sample findings:\n" + json.dumps(findings[:5], indent=2)
#         )

#         agent = assistant_factory(
#             name="agent_guidance",
#             system_message=system_msg,
#             temperature=0.2
#         )
#         messages = [
#             {"role": "system", "content": agent.system_message},
#             {"role": "user", "content": user_msg},
#         ]

#         md_path = self.out / "agent_guidance.md"
#         try:
#             md = agent.chat_completion_fn(messages) or ""
#             if not md.strip():
#                 md = (
#                     "*(No model content returned. This may happen if the model is loading or timed out.)*\n\n"
#                     f"Worst severity: {worst}\n\n"
#                     "By severity:\n"
#                     f"{json.dumps(by_sev, indent=2)}\n\n"
#                     "By tool:\n"
#                     f"{json.dumps(by_tool, indent=2)}\n\n"
#                     "Decision:\n"
#                     f"{json.dumps(decision, indent=2)}\n"
#                 )
#                 print("[reporter] LLM returned empty; writing fallback agent_guidance.md")
#             md_path.write_text(md, encoding="utf-8")
#             print(f"[reporter] Wrote {md_path}")
#             return str(md_path)
#         except Exception as e:
#             print(f"[reporter] LLM guidance error: {e}; writing fallback agent_guidance.md")
#             fallback = (
#                 "*(LLM error while generating guidance; fallback written.)*\n\n"
#                 f"Worst severity: {worst}\n\n"
#                 "By severity:\n"
#                 f"{json.dumps(by_sev, indent=2)}\n\n"
#                 "By tool:\n"
#                 f"{json.dumps(by_tool, indent=2)}\n\n"
#                 "Decision:\n"
#                 f"{json.dumps(decision, indent=2)}\n"
#             )
#             md_path.write_text(fallback, encoding="utf-8")
#             return str(md_path)

#     # ---------------------------------------------------------
#     # Main writer: metrics.json + optional LLM summary
#     # ---------------------------------------------------------
#     def emit(self, findings: List[Dict[str, Any]], decision: Dict[str, Any]):
#         """
#         Writes:
#         - metrics.json
#         - optionally metrics_explained.md (if LLM_EXPLAIN=1)
#         - optionally agent_guidance.md (if LLM_EXPLAIN=1)
#         """
#         self.out.mkdir(parents=True, exist_ok=True)

#         # Count findings by source
#         counts: Dict[str, int] = {}
#         for f in findings:
#             src = f.get("source", "other")
#             counts[src] = counts.get(src, 0) + 1

#         # Build metrics object
#         metrics = {
#             "counts": counts,
#             "total_findings": sum(counts.values()),
#             "gate_status": decision.get("status"),
#             "reason": decision.get("reason"),
#             # Backwards compatibility: include fail_count if derived
#             "fail_count": 1 if decision.get("status") == "fail" else 0,
#         }

#         # Write metrics.json
#         (self.out / "metrics.json").write_text(
#             json.dumps(metrics, indent=2),
#             encoding="utf-8"
#         )

#         # Optional LLM explanation
#         self._maybe_llm_explain(findings, decision)

#         # Optional LLM agent capability / best-practices guidance
#         self._maybe_llm_guidance(findings, decision)