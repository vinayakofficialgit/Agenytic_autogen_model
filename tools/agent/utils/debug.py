#!/usr/bin/env python3
import os
import json
import pathlib
from typing import List, Dict, Any

OUTDIR = pathlib.Path("agent_output")
OUTDIR.mkdir(parents=True, exist_ok=True)
TXT = OUTDIR / "rag_topk.txt"
JL  = OUTDIR / "rag_topk.jsonl"

def _enabled() -> bool:
    return (os.getenv("RAG_DEBUG", "false").lower() in ("1", "true", "yes"))

def _truncate(s: str, limit: int = 600) -> str:
    s = s or ""
    return s if len(s) <= limit else (s[:limit] + "\n…(truncated)…")

def log_topk(kind: str, finding: Dict[str, Any], query: str, topk: List[Dict[str,Any]], mode: str) -> None:
    """
    Append a short human-friendly block (TXT) and a JSONL entry
    summarizing the retrieval for this finding.
    """
    if not _enabled():
        return

    header = (
        f"[{mode.upper()}] {kind}  file={finding.get('file','')}  "
        f"line={finding.get('line',0)}  rule={finding.get('rule','')}\n"
        f"query: {query}\n"
    )
    lines = [header]
    for i, c in enumerate(topk or []):
        meta = c.get("meta", {})
        path = meta.get("path","")
        chunk = meta.get("chunk", 0)
        score = c.get("score", 0.0)
        snippet = _truncate(c.get("snippet",""))
        lines.append(f"  {i+1:02d}. score={score:.3f}  {path}#chunk{chunk}\n")
        if snippet:
            lines.append("      --- snippet ---\n")
            for ln in snippet.splitlines():
                lines.append(f"      {ln}\n")
            lines.append("      ---------------\n")
    lines.append("\n")

    TXT.write_text(TXT.read_text(encoding="utf-8") + "".join(lines), encoding="utf-8") if TXT.exists() else TXT.write_text("".join(lines), encoding="utf-8")

    # JSONL
    jl_entry = {
        "mode": mode,
        "kind": kind,
        "finding": {
            "file": finding.get("file"),
            "line": finding.get("line"),
            "rule": finding.get("rule"),
            "severity": finding.get("severity"),
            "detail": finding.get("detail"),
        },
        "query": query,
        "topk": [
            {
                "score": c.get("score"),
                "meta": c.get("meta"),
                "snippet": _truncate(c.get("snippet",""), 1000),
            } for c in (topk or [])
        ]
    }
    with JL.open("a", encoding="utf-8") as w:
        w.write(json.dumps(jl_entry) + "\n")