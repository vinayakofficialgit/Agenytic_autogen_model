# reporter.py
"""
Reporter Agent
--------------
Generates:
✔ metrics.json
✔ pr_comment.md
✔ merged AI enrichment
"""

from pathlib import Path
from typing import Dict, Any, List
import json


class Reporter:

    def __init__(self, config: Dict[str, Any], output_dir: Path):
        """Initialize reporter with config and output directory."""
        self.cfg = config or {}
        self.out = Path(output_dir)

    # -------------------------
    def _flatten(self, grouped):
        """Convert grouped findings into flat list."""
        flat = []
        for k, v in grouped.items():
            if k.startswith("_"):
                continue
            if isinstance(v, list):
                flat.extend(v)
        return [f for f in flat if isinstance(f, dict)]

    # -------------------------
    def _counts(self, findings, key):
        """Compute aggregated counts by key."""
        c = {}
        for f in findings:
            val = (f.get(key) or "unknown")
            c[val] = c.get(val, 0) + 1
        return c

    # -------------------------
    def _load_ai(self):
        """Load AI enrichment findings."""
        p = self.out / "ai_enriched_findings.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text()).get("enriched_findings", {})
        except Exception:
            return {}

    # -------------------------
    def _merge_ai(self, grouped, ai):
        """Safely merge AI enrichment using id matching."""
        for tool, items in ai.items():
            if tool not in grouped:
                continue
            lookup = {f.get("id"): f for f in grouped[tool]}
            for f in items:
                fid = f.get("id")
                if fid in lookup:
                    lookup[fid].update(f)

    # -------------------------
    def _emit_pr_comment(self, findings, decision):
        """Generate PR summary with severity and risk context."""
        lines = []
        gate = decision.get("decision", "PASS")

        lines.append(f"## Security Scan — {'FAIL' if gate=='FAIL' else 'PASS'}\n")

        sev = self._counts(findings, "severity")

        lines.append("### Severity Summary")
        for k in ["critical", "high", "medium", "low"]:
            lines.append(f"- {k}: {sev.get(k,0)}")

        risky = [f for f in findings if f.get("exploitability") == "high"]

        if risky:
            lines.append("\n### High Risk Findings")
            for r in risky[:5]:
                lines.append(f"- {r.get('title')} ({r.get('file')})")

        (self.out / "pr_comment.md").write_text("\n".join(lines))

    # -------------------------
    def _emit_metrics(self, findings, decision):
        """Generate metrics artifact."""
        metrics = {
            "total": len(findings),
            "by_severity": self._counts(findings, "severity"),
            "by_tool": self._counts(findings, "tool"),
            "by_category": self._counts(findings, "category"),
            "gate": decision.get("decision"),
        }
        (self.out / "metrics.json").write_text(json.dumps(metrics, indent=2))

    # -------------------------
    def emit(self, grouped, decision):
        """Main report generator entrypoint."""
        self.out.mkdir(parents=True, exist_ok=True)

        findings = self._flatten(grouped)

        ai = self._load_ai()
        self._merge_ai(grouped, ai)

        findings = self._flatten(grouped)

        self._emit_metrics(findings, decision)
        self._emit_pr_comment(findings, decision)

        print("[reporter] artifacts generated")