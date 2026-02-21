# collector.py
"""
CollectorAgent
--------------
Responsible for:
✔ Parsing scanner outputs
✔ Normalizing schema
✔ Grouping findings
✔ Producing flat + grouped outputs
NOTE:
❌ No LLM explanation here (belongs to triage layer)
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any
import json

# =====================================================
# Severity normalization mapping
# =====================================================
SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "low": "low",
    "info": "low",
    "unknown": "low",
}

# Confidence score per scanner (used later by policy gate)
CONFIDENCE = {
    "semgrep": 0.8,
    "spotbugs": 0.9,
    "trivy_fs": 0.8,
    "trivy_image": 0.9,
    "tfsec": 0.85,
    "gitleaks": 1.0,
    "zap": 0.5,
    "dependency-check": 0.9,
    "conftest": 0.7,
}


def _norm_sev(s):
    """Normalize scanner severity into canonical format."""
    if not s:
        return "low"
    return SEV_MAP.get(str(s).lower(), "low")


def _canonicalize(f: Dict[str, Any], tool: str) -> Dict[str, Any]:
    """Convert any tool finding into unified schema for downstream agents."""
    return {
        "tool": tool,
        "id": f.get("id") or f.get("rule_id") or f.get("vulnerability_id"),
        "title": f.get("title") or f.get("message") or f.get("summary"),
        "severity": _norm_sev(f.get("severity")),
        "file": f.get("file") or f.get("target"),
        "line": f.get("line"),
        "message": f.get("message") or f.get("description"),
        "_confidence": CONFIDENCE.get(tool, 0.6),
        "_raw": f,  # preserve original finding
    }

# =====================================================
# Parser imports (fallback safe)
# =====================================================
try:
    from tools.parsers import (
        parse_semgrep,
        parse_trivy_fs,
        parse_trivy_image,
        parse_tfsec,
        parse_gitleaks,
        parse_conftest,
        parse_zap,
        parse_dependency_check,
        parse_spotbugs,
    )
except Exception:
    # Safe fallbacks if parsers missing
    def parse_semgrep(p): return []
    def parse_trivy_fs(p): return []
    def parse_trivy_image(p): return []
    def parse_tfsec(p): return []
    def parse_gitleaks(p): return []
    def parse_conftest(p): return []
    def parse_zap(p): return []
    def parse_dependency_check(p): return []
    def parse_spotbugs(p): return []


# =====================================================
# Collector Agent
# =====================================================
class CollectorAgent:

    def __init__(self, config: Dict[str, Any], reports_dir: Path, output_dir: Path):
        """Initialize collector with config and directories."""
        self.cfg = config or {}
        self.reports = Path(reports_dir)
        self.out = Path(output_dir)
        self._parse_errors: List[str] = []

    # -------------------------------------------------
    # Safe parser wrapper
    # -------------------------------------------------
    def _safe_parse(self, fn, file: Path, tool_name: str) -> List[Dict[str, Any]]:
        """Safely parse scanner output and canonicalize results."""
        try:
            if not file.exists():
                return []
            items = fn(file) or []
            valid = [x for x in items if isinstance(x, dict)]
            return [_canonicalize(x, tool_name) for x in valid]
        except Exception as e:
            self._parse_errors.append(f"{tool_name}: {file} → {e}")
            return []

    # -------------------------------------------------
    # Load flat findings
    # -------------------------------------------------
    def load_all_flat(self) -> List[Dict[str, Any]]:
        """Collect findings from all scanners into a flat list."""
        findings: List[Dict[str, Any]] = []
        self._parse_errors = []

        findings += self._safe_parse(parse_semgrep, self.reports/"semgrep.json", "semgrep")
        findings += self._safe_parse(parse_trivy_fs, self.reports/"trivy_fs.json", "trivy_fs")
        findings += self._safe_parse(parse_trivy_image, self.reports/"trivy_image.json", "trivy_image")
        findings += self._safe_parse(parse_tfsec, self.reports/"tfsec.json", "tfsec")
        findings += self._safe_parse(parse_dependency_check, self.reports/"dependency-check.json", "dependency-check")
        findings += self._safe_parse(parse_spotbugs, self.reports/"spotbugs.json", "spotbugs")
        findings += self._safe_parse(parse_gitleaks, self.reports/"gitleaks.json", "gitleaks")

        # Multi-file conftest support
        for name in ["conftest-dockerfile.json","conftest_k8s.json","conftest_tf.json","conftest-remote.json"]:
            findings += self._safe_parse(parse_conftest, self.reports/name, "conftest")

        findings += self._safe_parse(parse_zap, self.reports/"zap.json", "zap")

        return findings

    # -------------------------------------------------
    # Load grouped findings
    # -------------------------------------------------
    def load_all(self) -> Dict[str, Any]:
        """Group flat findings by tool and produce metadata."""
        flat = self.load_all_flat()

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for f in flat:
            grouped.setdefault(f["tool"], []).append(f)

        grouped["_meta"] = {
            "count": len(flat),
            "by_tool": {k: len(v) for k, v in grouped.items() if not k.startswith("_")},
            "parse_errors": len(self._parse_errors),
        }

        # Write outputs for downstream agents
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out/"findings.json").write_text(json.dumps({"findings": flat}, indent=2))
        (self.out/"findings_grouped.json").write_text(json.dumps(grouped, indent=2))

        return grouped

    # -------------------------------------------------
    # Debug parse errors
    # -------------------------------------------------
    def get_parse_errors(self) -> List[str]:
        """Return parser errors for troubleshooting."""
        return self._parse_errors.copy()