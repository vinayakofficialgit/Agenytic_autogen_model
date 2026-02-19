# # policy_gate.py
# """
# Enhanced PolicyGate for DevSecOps Agentic AI Pipeline

# Evaluates normalized findings and decides whether to fail the pipeline and/or open a remediation PR.

# Key Enhancements:
# - Better LLM integration with fallback support
# - Improved error handling and logging
# - More detailed policy evaluation
# - Support for custom severity thresholds

# Inputs (flexible):
#   - Typically receives `findings` from main.py (CollectorAgent or similar), which may be:
#       * a FLAT list of finding dicts, or
#       * a GROUPED dict (e.g., {"semgrep":[...], "trivy_fs":[...], ...})
#   - OR can read a pre-merged file agent_output/merged_findings.json (when run as __main__)

# Outputs:
#   - agent_output/decision.json
#   - agent_output/policy_summary.md
#   - agent_output/policy_explained.md (optional, if LLM_EXPLAIN=1)

# Tuning (via environment variables):
#   - MIN_SEVERITY => "low|medium|high|critical" (default: "critical")
#   - MAX_FINDINGS_TOTAL => integer limit (optional)
#   - MAX_PER_CATEGORY_code/infra/image/policy/secrets/webapp => per-category caps
#   - ALLOW_TOOLS => comma-separated tools to ignore in gating
#   - DENY_TOOLS => comma-separated tools that always count in gating
#   - SEVERITY_WEIGHTS => JSON mapping e.g. {"low":1,"medium":2,"high":3,"critical":5}
#   - LLM_EXPLAIN => "1" to generate explanations via llm_bridge/Ollama
# """


from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

CATEGORIES = ("code","infra","image","policy","secrets","webapp","sca")

def _norm_sev(s: Optional[str]) -> str:
    return (s or "low").strip().lower()

def _sev_rank(s: Optional[str]) -> int:
    return SEV_ORDER.get(_norm_sev(s), 1)

def _int_env(name: str, default: Optional[int]) -> Optional[int]:
    val=os.getenv(name)
    try: return int(val) if val else default
    except: return default

def _csv_env(name: str)->List[str]:
    val=os.getenv(name)
    return [x.strip().lower() for x in val.split(",")] if val else []

def _json_env(name: str, default: Dict[str, Any]) -> Dict[str, Any]:
    val=os.getenv(name)
    try: return json.loads(val) if val else default
    except: return default

@dataclass
class PolicyConfig:
    min_severity:str="critical"
    max_total:Optional[int]=None
    max_per_category:Optional[Dict[str,int]]=None
    allow_tools:List[str]=field(default_factory=list)
    deny_tools:List[str]=field(default_factory=list)
    severity_weights:Optional[Dict[str,int]]=None

def load_policy_config()->PolicyConfig:
    min_sev=os.getenv("MIN_SEVERITY","critical").lower()
    max_total=_int_env("MAX_FINDINGS_TOTAL",None)

    per_cat={}
    for c in CATEGORIES:
        v=_int_env(f"MAX_PER_CATEGORY_{c}",None)
        if v is not None: per_cat[c]=v

    return PolicyConfig(
        min_severity=min_sev,
        max_total=max_total,
        max_per_category=per_cat or None,
        allow_tools=_csv_env("ALLOW_TOOLS"),
        deny_tools=_csv_env("DENY_TOOLS"),
        severity_weights=_json_env("SEVERITY_WEIGHTS",SEV_ORDER)
    )

_GROUP_TO_CATEGORY={
    "semgrep":"code",
    "spotbugs":"code",
    "trivy_fs":"infra",
    "tfsec":"infra",
    "trivy_image":"image",
    "gitleaks":"secrets",
    "conftest":"policy",
    "zap":"webapp",
    "dependency-check":"sca",
    "dependency_check":"sca"
}

def _as_location(f):
    file=f.get("file") or f.get("path") or ""
    line=f.get("line")
    return f"{file}:{line}" if file and line else file

def _flatten_findings_input(findings):
    flat=[]
    if isinstance(findings,list):
        for f in findings:
            g=dict(f)
            g["severity"]=_norm_sev(g.get("severity"))
            g["tool"]=(g.get("tool") or "").lower()
            g["category"]=g.get("category") or _GROUP_TO_CATEGORY.get(g["tool"],"")
            g["location"]=g.get("location") or _as_location(g)
            flat.append(g)
    elif isinstance(findings,dict):
        for tool,items in findings.items():
            if not isinstance(items,list): continue
            for it in items:
                g=dict(it)
                g["severity"]=_norm_sev(g.get("severity"))
                g["tool"]=tool
                g["category"]=g.get("category") or _GROUP_TO_CATEGORY.get(tool,"")
                g["location"]=g.get("location") or _as_location(g)
                g["id"]=g.get("id") or g.get("rule_id")
                g["message"]=g.get("message") or g.get("summary")
                flat.append(g)
    return flat

def summarize(findings,cfg):
    by_sev={k:0 for k in SEV_ORDER}
    by_cat={c:0 for c in CATEGORIES}
    by_tool={}
    worst="low"
    total=0

    for f in findings:
        sev=_norm_sev(f.get("severity"))
        cat=f.get("category","")
        tool=f.get("tool","")

        total+=1
        by_sev[sev]+=1
        if cat in by_cat: by_cat[cat]+=1
        by_tool[tool]=by_tool.get(tool,0)+1
        if _sev_rank(sev)>_sev_rank(worst): worst=sev

    weights=cfg.severity_weights or SEV_ORDER
    score=sum(by_sev[k]*weights.get(k,1) for k in by_sev)

    return dict(
        total=total,
        by_severity=by_sev,
        by_category=by_cat,
        by_tool=by_tool,
        worst_severity=worst,
        weighted_score=score
    )

def gate(stats,findings,cfg):
    violations=[]
    min_rank=_sev_rank(cfg.min_severity)
    allow=set(cfg.allow_tools)
    deny=set(cfg.deny_tools)

    for f in findings:
        tool=f.get("tool")
        sev_rank=_sev_rank(f.get("severity"))

        if tool in allow and tool not in deny: continue

        if sev_rank>=min_rank:
            violations.append({
                "tool":tool,
                "severity":f.get("severity"),
                "category":f.get("category"),
                "location":f.get("location"),
                "id":f.get("id"),
                "message":f.get("message")
            })

    if violations:
        return True,f"{violations[0]['severity']} violation detected",violations

    if cfg.max_total and stats["total"]>cfg.max_total:
        return True,"Total findings exceed cap",[]

    if cfg.max_per_category:
        for c,cap in cfg.max_per_category.items():
            if stats["by_category"].get(c,0)>cap:
                return True,f"{c} cap exceeded",[]

    return False,"Within policy",[]

class PolicyGate:
    def __init__(self,cfg,output_dir):
        self.cfg=cfg or {}
        self.out_dir=Path(output_dir)

    def decide(self,findings_input):
        findings=_flatten_findings_input(findings_input)
        policy_cfg=load_policy_config()

        stats=summarize(findings,policy_cfg)
        fail,reason,violations=gate(stats,findings,policy_cfg)

        decision=dict(
            open_pr=bool(fail),
            status="fail" if fail else "ok",
            reason=reason,
            stats=stats,
            violations=violations[:10]
        )

        self.out_dir.mkdir(parents=True,exist_ok=True)
        (self.out_dir/"decision.json").write_text(json.dumps(decision,indent=2))
        return decision

if __name__=="__main__":
    merged=Path("agent_output/merged_findings.json")
    findings=[]
    if merged.exists():
        findings=json.loads(merged.read_text()).get("findings",[])
    decision=PolicyGate({},Path("agent_output")).decide(findings)
    print(json.dumps(decision,indent=2))
    sys.exit(1 if decision["status"]=="fail" else 0)