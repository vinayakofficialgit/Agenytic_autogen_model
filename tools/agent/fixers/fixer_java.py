#!/usr/bin/env python3
import pathlib
import subprocess
from typing import Dict, Any, List


# ============================================================
# AST Rule Mapping
# ============================================================

RULE_MAP = {
    "sql-injection": "SqlInjectionFixer",
    "weak-random": "WeakRandomFixer",
    "md5-usage": "MD5Fixer",
    "command-injection": "CommandInjectionFixer",
}


def query_for(item: dict) -> str:
    return "secure java coding example remediation"


# ============================================================
# Path Helpers
# ============================================================

def _resolve_full_path(path: str) -> str:
    p = pathlib.Path(path)

    if p.exists():
        return str(p)

    prefixed = pathlib.Path("java-pilot-app") / p
    if prefixed.exists():
        return str(prefixed)

    return ""


def _read(path: str) -> str:
    p = pathlib.Path(path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")


# ============================================================
# AST Deterministic Fix
# ============================================================

def try_deterministic(item: dict) -> Dict[str, str] | None:
    raw_path = item.get("file", "")
    if not raw_path.endswith(".java"):
        return None

    path = _resolve_full_path(raw_path)
    if not path:
        print(f"⚠ Java file not found: {raw_path}")
        return None

    original = _read(path)
    if not original.strip():
        return None

    rule_id = _map_rule(item)
    if not rule_id:
        return None

    print(f"→ AST Rule Triggered: {rule_id}")

    try:
        subprocess.run(
            [
                "java",
                "-cp",
                "tools/java-ast-fixer/target/classes",
                "com.enterprise.astfixer.AstFixerMain",
                path,
                rule_id
            ],
            check=True
        )
    except Exception as e:
        print(f"⚠ AST engine failed: {e}")
        return None

    modified = _read(path)

    if modified == original:
        print("⚠ AST rule applied no changes")
        return None

    if len(modified.strip()) == 0:
        print("⚠ AST produced empty file — skipping")
        return None

    if len(modified) < len(original) * 0.5:
        print("⚠ AST rewrite suspiciously small — skipping")
        return None

    return {
        "file": path,
        "content": modified
    }


# ============================================================
# Rule Mapper
# ============================================================

def _map_rule(item: dict) -> str | None:
    rule = (item.get("rule") or "").lower()
    detail = (item.get("detail") or "").lower()

    if "sql" in rule or "sql" in detail:
        return "SqlInjectionFixer"

    if "random" in rule:
        return "WeakRandomFixer"

    if "md5" in rule:
        return "MD5Fixer"

    if "command" in rule:
        return "CommandInjectionFixer"

    return None


# ============================================================
# RAG Fallback (Optional)
# ============================================================

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
    return None