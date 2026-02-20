from pathlib import Path
from typing import Dict, Any, List, Union
import json
import os


class Reporter:

    def __init__(self, config: Dict[str, Any], output_dir: Path):
        self.cfg = config or {}
        self.out = Path(output_dir)

    # -------------------------
    # helpers
    # -------------------------
    def _flatten(self, grouped):
        flat = []
        if isinstance(grouped, dict):
            for k,v in grouped.items():
                if k.startswith("_"):
                    continue
                if isinstance(v,list):
                    flat.extend(v)
        return [f for f in flat if isinstance(f,dict)]

    def _counts(self, findings, key):
        c={}
        for f in findings:
            val=(f.get(key) or "unknown")
            c[val]=c.get(val,0)+1
        return c

    # -------------------------
    # load AI enrichment
    # -------------------------
    def _load_ai(self):
        p=self.out/"ai_enriched_findings.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text()).get("enriched_findings",{})
        except:
            return {}

    # -------------------------
    # PR summary (risk aware)
    # -------------------------
    def _emit_pr_comment(self, findings, decision):
        lines=[]
        gate=decision.get("decision","PASS")

        lines.append(f"## 🛡️ Security Scan — {'❌ FAIL' if gate=='FAIL' else '✅ PASS'}")
        lines.append("")

        sev=self._counts(findings,"severity")
        lines.append("### Summary")
        lines.append(f"- Critical: {sev.get('critical',0)}")
        lines.append(f"- High: {sev.get('high',0)}")
        lines.append(f"- Medium: {sev.get('medium',0)}")
        lines.append(f"- Low: {sev.get('low',0)}")
        lines.append("")

        # ⭐ risk enriched top findings
        risky=[f for f in findings if f.get("exploitability") in ["high","critical"]]

        if risky:
            lines.append("### 🚨 High Risk Findings")
            for r in risky[:5]:
                lines.append(
                    f"- [{r.get('severity')}] {r.get('file','')} "
                    f"(exploitability={r.get('exploitability')}, autofix={r.get('autofix_possible')})"
                )

        (self.out/"pr_comment.md").write_text("\n".join(lines))

    # -------------------------
    # metrics
    # -------------------------
    def _emit_metrics(self, findings, decision):
        metrics={
            "total":len(findings),
            "by_severity":self._counts(findings,"severity"),
            "by_tool":self._counts(findings,"tool"),
            "gate":decision.get("decision"),
            "reason":decision.get("reason"),
        }
        (self.out/"metrics.json").write_text(json.dumps(metrics,indent=2))

    # -------------------------
    # main emit
    # -------------------------
    def emit(self, grouped, decision):

        self.out.mkdir(parents=True, exist_ok=True)

        findings=self._flatten(grouped)

        # merge AI enrichment
        ai=self._load_ai()
        for tool,items in ai.items():
            if tool in grouped:
                for i,f in enumerate(items):
                    if i<len(grouped[tool]):
                        grouped[tool][i].update(f)

        findings=self._flatten(grouped)

        self._emit_metrics(findings,decision)
        self._emit_pr_comment(findings,decision)

        print("[reporter] artifacts generated")