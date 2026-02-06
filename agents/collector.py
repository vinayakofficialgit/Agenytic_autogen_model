    
    
    
    
    
    
 # collector.py
"""
Enhanced CollectorAgent for DevSecOps Agentic AI Pipeline

Key Enhancements:
- Better error handling and logging
- Improved LLM integration with fallback support
- Robust parsing with detailed error messages
- Support for grouped and flat output formats
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import json
import os
import sys

# --------------------------
# Robust imports
# --------------------------

# llm_bridge: works if it's in agents/ or at the repo root
try:
    from agents.llm_bridge import (
        assistant_factory,
        ollama_chat,
        get_fallback_suggestion,
        check_ollama_health,
    )
except Exception:
    try:
        from llm_bridge import (
            assistant_factory,
            ollama_chat,
            get_fallback_suggestion,
            check_ollama_health,
        )
    except Exception:
        assistant_factory = None
        ollama_chat = None
        get_fallback_suggestion = None
        check_ollama_health = None

# tools.parsers: prefer package import; fall back by adding repo root to sys.path
try:
    from tools.parsers import (
        parse_semgrep,
        parse_trivy_fs,
        parse_trivy_image,
        parse_tfsec,
        parse_gitleaks,
        parse_conftest,
        parse_zap,
    )
except Exception:
    try:
        repo_root = Path(__file__).resolve().parents[1]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from tools.parsers import (
            parse_semgrep,
            parse_trivy_fs,
            parse_trivy_image,
            parse_tfsec,
            parse_gitleaks,
            parse_conftest,
            parse_zap,
        )
    except Exception as _e:
        # Create stub parsers that return empty lists
        print(f"[collector] Warning: Could not import tools.parsers: {_e}")
        print("[collector] Using stub parsers that return empty lists")
        
        def parse_semgrep(path): return []
        def parse_trivy_fs(path): return []
        def parse_trivy_image(path): return []
        def parse_tfsec(path): return []
        def parse_gitleaks(path): return []
        def parse_conftest(path): return []
        def parse_zap(path): return []


def _llm_ask(name: str, system: str, user: str, temperature: float = 0.2) -> Optional[str]:
    """
    Convenience helper to ask the LLM through assistant_factory.
    Returns None if llm_bridge is not available.
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
        print(f"[collector] LLM error in _llm_ask: {e}")
        return None


def _llm_banner() -> str:
    """Small banner showing LLM configuration."""
    url = os.getenv("OLLAMA_URL", "(unset)")
    model = os.getenv("OLLAMA_MODEL", "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


class CollectorAgent:
    """
    CollectorAgent aggregates raw findings from scanning tools under `reports/`.

    Enhancements:
      - Safe handling of missing/malformed files with detailed logging
      - Optional deduplication (cfg["dedup_keys"])
      - Optional normalization of severity to lowercase
      - Emits BOTH flat and grouped outputs:
          * flat list (backward compatible)
          * grouped dict (normalized for LLM layer)
      - Optional LLM summarization via llm_bridge if LLM_EXPLAIN=1
      - Writes merged JSON dumps to:
          * output_dir/findings.json (flat)
          * output_dir/findings_grouped.json (grouped & normalized)
    """

    def __init__(self, config: Dict[str, Any], reports_dir: Path, output_dir: Path):
        self.cfg = config or {}
        self.reports = Path(reports_dir)
        self.out = Path(output_dir)
        self._parse_errors: List[str] = []  # Track parsing errors

    # --------------------------
    # Parser helper
    # --------------------------
    def _safe_parse(self, fn, file: Path, tool_name: str = "") -> List[Dict[str, Any]]:
        """
        Call parser `fn` safely; return [] on missing or malformed file.
        Logs detailed error information for debugging.
        """
        try:
            if not file.exists():
                # Not an error - file may simply not exist if scanner wasn't run
                return []
            
            result = fn(file)
            
            if result is None:
                self._parse_errors.append(f"{tool_name}: Parser returned None for {file}")
                return []
            
            if not isinstance(result, list):
                self._parse_errors.append(f"{tool_name}: Parser returned {type(result).__name__} instead of list for {file}")
                return []
            
            # Guard: keep only dict entries
            valid_items = [x for x in result if isinstance(x, dict)]
            invalid_count = len(result) - len(valid_items)
            
            if invalid_count > 0:
                self._parse_errors.append(f"{tool_name}: Skipped {invalid_count} non-dict items from {file}")
            
            if valid_items:
                print(f"[collector] Parsed {len(valid_items)} findings from {tool_name} ({file.name})")
            
            return valid_items
            
        except json.JSONDecodeError as e:
            self._parse_errors.append(f"{tool_name}: JSON decode error in {file}: {e}")
            return []
        except Exception as e:
            self._parse_errors.append(f"{tool_name}: Error parsing {file}: {e}")
            return []

    # --------------------------
    # Normalization helpers for LLM
    # --------------------------
    @staticmethod
    def _first_nonempty(*vals: Any, default: Any = "") -> Any:
        """Return first non-empty value from arguments."""
        for v in vals:
            if v is None:
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            return v
        return default

    def _norm_semgrep_item(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize semgrep finding into the structure the LLM layer expects.
        Expected keys: file, line, severity, rule_id, message, snippet
        """
        file = self._first_nonempty(
            f.get("file"),
            (f.get("location") or {}).get("file") if isinstance(f.get("location"), dict) else None,
            f.get("path"),
            default="(unknown)"
        )
        
        line = self._first_nonempty(
            f.get("line"),
            (f.get("location") or {}).get("line") if isinstance(f.get("location"), dict) else None,
            (f.get("start") or {}).get("line"),
            f.get("start_line"),
            default=""
        )
        
        rule_id = self._first_nonempty(
            f.get("rule_id"),
            f.get("check_id"),
            f.get("id"),
            default=""
        )
        
        message = self._first_nonempty(
            f.get("message"),
            f.get("title"),
            f.get("description"),
            default=""
        )
        
        severity = (f.get("severity") or "low")
        if isinstance(severity, str):
            severity = severity.strip().lower()
        
        snippet = self._first_nonempty(
            f.get("snippet"),
            f.get("code"),
            f.get("content"),
            (f.get("extra") or {}).get("lines") if isinstance(f.get("extra"), dict) else None,
            default=""
        )

        # Cast line to int if possible
        try:
            line = int(line) if (line != "" and line is not None) else ""
        except Exception:
            pass

        return {
            "file": file,
            "line": line,
            "severity": severity,
            "rule_id": rule_id,
            "message": message,
            "snippet": snippet,
        }

    def _norm_trivy_fs_item(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize trivy-fs/config finding for LLM:
        Expected keys: file, id, severity, summary, snippet
        """
        file = self._first_nonempty(
            f.get("file"),
            f.get("target"),
            f.get("path"),
            default="(unknown)"
        )
        
        fid = self._first_nonempty(
            f.get("id"),
            f.get("rule_id"),
            f.get("vulnerability_id"),
            f.get("class_id"),
            default=""
        )
        
        severity = (f.get("severity") or "low")
        if isinstance(severity, str):
            severity = severity.strip().lower()
        
        summary = self._first_nonempty(
            f.get("summary"),
            f.get("message"),
            f.get("title"),
            f.get("description"),
            default=""
        )
        
        snippet = self._first_nonempty(
            f.get("snippet"),
            f.get("code"),
            f.get("content"),
            default=""
        )

        return {
            "file": file,
            "id": fid,
            "severity": severity,
            "summary": summary,
            "snippet": snippet,
        }

    def _norm_trivy_image_item(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize trivy-image finding."""
        return {
            "package": self._first_nonempty(f.get("package"), f.get("PkgName"), default=""),
            "version": self._first_nonempty(f.get("version"), f.get("InstalledVersion"), default=""),
            "fixed_version": self._first_nonempty(f.get("fixed_version"), f.get("FixedVersion"), default=""),
            "vulnerability_id": self._first_nonempty(f.get("vulnerability_id"), f.get("VulnerabilityID"), f.get("id"), default=""),
            "severity": (f.get("severity") or f.get("Severity") or "low").lower(),
            "title": self._first_nonempty(f.get("title"), f.get("Title"), f.get("description"), default=""),
            "target": self._first_nonempty(f.get("target"), f.get("Target"), default=""),
        }

    def _norm_gitleaks_item(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize gitleaks finding."""
        return {
            "file": self._first_nonempty(f.get("file"), f.get("File"), default=""),
            "line": f.get("line") or f.get("StartLine") or "",
            "rule_id": self._first_nonempty(f.get("rule_id"), f.get("RuleID"), f.get("rule"), default=""),
            "secret": self._first_nonempty(f.get("secret"), f.get("Secret"), default="[REDACTED]")[:20] + "...",
            "commit": self._first_nonempty(f.get("commit"), f.get("Commit"), default=""),
            "severity": "high",  # Secrets are always high severity
        }

    # --------------------------
    # Main collector
    # --------------------------
    def load_all_flat(self) -> List[Dict[str, Any]]:
        """
        Load findings from all tools and return a FLAT list (backward compatible).
        """
        findings: List[Dict[str, Any]] = []
        self._parse_errors = []  # Reset errors

        # Semgrep
        semgrep_items = self._safe_parse(parse_semgrep, self.reports / "semgrep.json", "semgrep")
        for it in semgrep_items:
            it.setdefault("tool", "semgrep")
            it.setdefault("category", "code")
        findings += semgrep_items

        # Trivy FS
        trivy_fs_items = self._safe_parse(parse_trivy_fs, self.reports / "trivy.json", "trivy-fs")
        for it in trivy_fs_items:
            it.setdefault("tool", "trivy-fs")
            it.setdefault("category", "infra")
        findings += trivy_fs_items

        # Trivy Image
        trivy_image_items = self._safe_parse(parse_trivy_image, self.reports / "trivy-image.json", "trivy-image")
        for it in trivy_image_items:
            it.setdefault("tool", "trivy-image")
            it.setdefault("category", "image")
        findings += trivy_image_items

        # Tfsec
        tfsec_items = self._safe_parse(parse_tfsec, self.reports / "tfsec.json", "tfsec")
        for it in tfsec_items:
            it.setdefault("tool", "tfsec")
            it.setdefault("category", "infra")
        findings += tfsec_items

        # Gitleaks
        gitleaks_items = self._safe_parse(parse_gitleaks, self.reports / "gitleaks.json", "gitleaks")
        for it in gitleaks_items:
            it.setdefault("tool", "gitleaks")
            it.setdefault("category", "secrets")
        findings += gitleaks_items

        # Conftest family
        conftest_files = [
            ("conftest-dockerfile.json", "dockerfile"),
            ("conftest-k8s.json", "kubernetes"),
            ("conftest-terraform.json", "terraform"),
            ("conftest-remote.json", "remote"),
        ]
        for name, subtype in conftest_files:
            conf_items = self._safe_parse(parse_conftest, self.reports / name, f"conftest-{subtype}")
            for it in conf_items:
                it.setdefault("tool", "conftest")
                it.setdefault("category", "policy")
                it.setdefault("subtype", subtype)
            findings += conf_items

        # ZAP
        zap_items = self._safe_parse(parse_zap, self.reports / "zap.json", "zap")
        for it in zap_items:
            it.setdefault("tool", "zap")
            it.setdefault("category", "webapp")
        findings += zap_items

        # Optional: normalize severity
        if self.cfg.get("normalize_severity", True):
            for f in findings:
                sev = (f.get("severity") or "low")
                if isinstance(sev, str):
                    sev = sev.strip().lower()
                f["severity"] = sev

        # Optional deduplication
        dedup_keys = self.cfg.get("dedup_keys")
        if dedup_keys:
            before_count = len(findings)
            findings = self._dedupe(findings, dedup_keys)
            deduped = before_count - len(findings)
            if deduped > 0:
                print(f"[collector] Deduplicated {deduped} findings")

        # Log any parse errors
        if self._parse_errors:
            print(f"[collector] Encountered {len(self._parse_errors)} parsing issue(s):")
            for err in self._parse_errors[:5]:  # Show first 5
                print(f"  - {err}")
            if len(self._parse_errors) > 5:
                print(f"  - ... and {len(self._parse_errors) - 5} more")

        return findings

    def _group_for_llm(self, flat: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build grouped + normalized structure suitable for LLM prompts.
        Keys present even if empty to simplify downstream logic.
        """
        grouped: Dict[str, List[Dict[str, Any]]] = {
            "semgrep": [],
            "trivy_fs": [],
            "trivy_image": [],
            "tfsec": [],
            "gitleaks": [],
            "conftest": [],
            "zap": [],
        }

        for f in flat:
            # Guard: skip non-dict entries
            if not isinstance(f, dict):
                continue

            tool = (f.get("tool") or f.get("source") or "").lower()

            if tool == "semgrep":
                grouped["semgrep"].append(self._norm_semgrep_item(f))
            elif tool in ("trivy-fs", "trivy", "trivy_config", "trivy-config", "trivyfs"):
                grouped["trivy_fs"].append(self._norm_trivy_fs_item(f))
            elif tool in ("trivy-image", "trivy_image"):
                grouped["trivy_image"].append(self._norm_trivy_image_item(f))
            elif tool == "tfsec":
                grouped["tfsec"].append(f)
            elif tool == "gitleaks":
                grouped["gitleaks"].append(self._norm_gitleaks_item(f))
            elif tool == "conftest":
                grouped["conftest"].append(f)
            elif tool == "zap":
                grouped["zap"].append(f)
            else:
                # Put unknown tool outputs in 'conftest' bucket to avoid losing them
                grouped["conftest"].append(f)

        return grouped

    def load_all(self) -> Dict[str, Any]:
        """
        Load findings from all tools and return a GROUPED dict (LLM-ready), while
        also writing the flat list to findings.json for backward compatibility.
        """
        flat = self.load_all_flat()

        # Optional: write merged findings flat json
        if self.cfg.get("write_output", True):
            self._write_output_flat(flat)

        grouped = self._group_for_llm(flat)

        # Optional: write grouped json
        if self.cfg.get("write_output", True):
            self._write_output_grouped(grouped)

        # Optional: LLM explain summary (only if explicitly enabled)
        if os.getenv("LLM_EXPLAIN", "").strip() == "1":
            self._maybe_llm_explain(flat)

        # Add metadata
        grouped["_meta"] = {
            "count": sum(len(v) for k, v in grouped.items() if not k.startswith("_")),
            "flat_count": len(flat),
            "by_tool": {k: len(v) for k, v in grouped.items() if not k.startswith("_")},
            "parse_errors": len(self._parse_errors),
        }
        
        return grouped

    # --------------------------
    # Deduplication
    # --------------------------
    def _dedupe(self, findings: List[Dict[str, Any]], keys: List[str]) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on key fields."""
        seen = set()
        out: List[Dict[str, Any]] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            sig = tuple(f.get(k) for k in keys)
            if sig not in seen:
                seen.add(sig)
                out.append(f)
        return out

    # --------------------------
    # Write outputs
    # --------------------------
    def _write_output_flat(self, findings: List[Dict[str, Any]]):
        """Write flat findings list to JSON."""
        self.out.mkdir(parents=True, exist_ok=True)
        payload = {"findings": findings, "count": len(findings)}
        try:
            (self.out / "findings.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            print(f"[collector] Error writing findings.json: {e}")

    def _write_output_grouped(self, grouped: Dict[str, Any]):
        """Write grouped findings to JSON."""
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            (self.out / "findings_grouped.json").write_text(
                json.dumps(grouped, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            print(f"[collector] Error writing findings_grouped.json: {e}")

    # --------------------------
    # Optional LLM explanation
    # --------------------------
    def _maybe_llm_explain(self, flat_findings: List[Dict[str, Any]]) -> Optional[str]:
        """
        If LLM_EXPLAIN=1 and llm_bridge.py is present, generate a summary of what scanners reported.
        """
        # Simple grouping by source/tool
        by_tool: Dict[str, int] = {}
        for f in flat_findings:
            if not isinstance(f, dict):
                continue
            t = (f.get("tool") or f.get("source") or "unknown")
            by_tool[t] = by_tool.get(t, 0) + 1

        if not by_tool:
            return None

        system_msg = (
            "You are a DevSecOps assistant. Summarize security scan findings across tools. "
            "Be concise, factual, and avoid hallucinations. Highlight critical/high severity items. "
            "Keep it under 200 words."
        )

        user_msg = (
            "Summaries needed from aggregated scan findings.\n\n"
            "Counts by tool:\n"
            f"{json.dumps(by_tool, indent=2)}\n\n"
            "Example findings (first 5):\n"
            + json.dumps([x for x in flat_findings[:5] if isinstance(x, dict)], indent=2)
        )

        summary = _llm_ask(
            name="collector_summary",
            system=system_msg,
            user=user_msg,
            temperature=0.2,
        )
        
        if summary:
            self.out.mkdir(parents=True, exist_ok=True)
            path = self.out / "collector_summary.md"
            try:
                path.write_text(_llm_banner() + summary.strip(), encoding="utf-8")
                print(f"[collector] Wrote LLM summary to {path}")
                return str(path)
            except Exception as e:
                print(f"[collector] Error writing summary: {e}")
        
        return None

    def get_parse_errors(self) -> List[str]:
        """Return list of parsing errors encountered during collection."""
        return self._parse_errors.copy()