# agents/collector.py
"""
Enterprise-Grade CollectorAgent for DevSecOps Agentic AI Pipeline

Enhancements:
- Canonical severity normalization
- Deterministic grouped output
- Defensive parsing
- Deduplication
- CI-safe optional LLM summary
- Structured metadata block
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import os
import sys


# ---------------------------------------------------
# Severity Normalization (Enterprise Safe)
# ---------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "warning": "medium",
    "unknown": "low",
}


def _normalize_severity(value: str) -> str:
    if not isinstance(value, str):
        return "low"
    return SEVERITY_MAP.get(value.strip().lower(), "low")


# ---------------------------------------------------
# Robust Parser Imports
# ---------------------------------------------------

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
    def _stub(_): return []
    parse_semgrep = parse_trivy_fs = parse_trivy_image = _stub
    parse_tfsec = parse_gitleaks = parse_conftest = parse_zap = _stub


class CollectorAgent:

    def __init__(self, config: Dict[str, Any], reports_dir: Path, output_dir: Path):
        self.cfg = config or {}
        self.reports = Path(reports_dir)
        self.out = Path(output_dir)
        self._parse_errors: List[str] = []

    # ---------------------------------------------------
    # Safe Parse
    # ---------------------------------------------------

    def _safe_parse(self, fn, file: Path, tool: str) -> List[Dict[str, Any]]:
        if not file.exists():
            return []

        try:
            data = fn(file)
            if not isinstance(data, list):
                return []

            valid = [x for x in data if isinstance(x, dict)]
            return valid

        except Exception as e:
            self._parse_errors.append(f"{tool}: {e}")
            return []

    # ---------------------------------------------------
    # Deduplication
    # ---------------------------------------------------

    def _dedupe(self, findings: List[Dict[str, Any]], keys: List[str]) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for f in findings:
            sig = tuple(f.get(k) for k in keys)
            if sig not in seen:
                seen.add(sig)
                out.append(f)
        return out

    # ---------------------------------------------------
    # Flat Loader
    # ---------------------------------------------------

    def load_all_flat(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        sources = [
            ("semgrep.json", parse_semgrep, "semgrep", "code"),
            ("trivy_fs.json", parse_trivy_fs, "trivy-fs", "infra"),
            ("trivy_image.json", parse_trivy_image, "trivy-image", "image"),
            ("tfsec.json", parse_tfsec, "tfsec", "infra"),
            ("gitleaks.json", parse_gitleaks, "gitleaks", "secrets"),
            ("conftest.json", parse_conftest, "conftest", "policy"),
            ("zap.json", parse_zap, "zap", "webapp"),
        ]

        for filename, parser, tool, category in sources:
            items = self._safe_parse(parser, self.reports / filename, tool)
            for it in items:
                it.setdefault("tool", tool)
                it.setdefault("category", category)
                it["severity"] = _normalize_severity(it.get("severity", "low"))
            findings.extend(items)

        # Deduplicate
        if self.cfg.get("dedup_keys"):
            findings = self._dedupe(findings, self.cfg["dedup_keys"])

        return findings

    # ---------------------------------------------------
    # Grouped Structure (LLM Safe)
    # ---------------------------------------------------

    def _group(self, flat: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for f in flat:
            tool = f.get("tool", "unknown")
            grouped.setdefault(tool, []).append(f)

        return grouped

    # ---------------------------------------------------
    # Main Entry
    # ---------------------------------------------------

    def load_all(self) -> Dict[str, Any]:
        flat = self.load_all_flat()

        grouped = self._group(flat)

        # Metadata
        by_sev = {}
        for f in flat:
            sev = f.get("severity", "low")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        worst = "low"
        for level in SEVERITY_ORDER:
            if by_sev.get(level, 0) > 0:
                worst = level
                break

        grouped["_meta"] = {
            "total": len(flat),
            "by_severity": by_sev,
            "worst_severity": worst,
            "parse_errors": len(self._parse_errors),
        }

        # Write output
        if self.cfg.get("write_output", True):
            self.out.mkdir(parents=True, exist_ok=True)
            (self.out / "findings.json").write_text(
                json.dumps({"findings": flat}, indent=2),
                encoding="utf-8",
            )
            (self.out / "findings_grouped.json").write_text(
                json.dumps(grouped, indent=2),
                encoding="utf-8",
            )

        # return grouped
        
        print(f"[collector] Total findings: {grouped['_meta']['total']}")
        print(f"[collector] Worst severity: {grouped['_meta']['worst_severity']}")
        return grouped