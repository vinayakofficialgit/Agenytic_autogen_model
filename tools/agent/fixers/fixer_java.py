#!/usr/bin/env python3
import pathlib
import re
from typing import List, Dict, Any


# ============================================================
# Query Builder
# ============================================================

def query_for(item: dict) -> str:
    return "java spring jdbc JdbcTemplate prepared statement parameterized query"


# ============================================================
# Helpers
# ============================================================

def _read(path: str) -> str:
    p = pathlib.Path(path)
    if not p.exists():
        return ""
    data = p.read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")


def _resolve_full_path(path: str) -> str:
    """
    Fix path mismatch from scanner output.
    Scanners may return:
        src/main/java/...
    But actual file is:
        java-pilot-app/src/main/java/...
    """
    p = pathlib.Path(path)

    if p.exists():
        return str(p)

    prefixed = pathlib.Path("java-pilot-app") / p
    if prefixed.exists():
        return str(prefixed)

    return ""


# ============================================================
# Deterministic SQL Injection Fix
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
    if not original:
        return None

    modified = original

    # Match vulnerable SQL concatenation pattern
    pattern = re.compile(
        r'(?ms)^([ \t]*)String\s+sql\s*=\s*"SELECT\s+\*\s+FROM\s+USERS\s+WHERE\s+NAME\s*=\s*\'"\s*\+\s*name\s*\+\s*"\'";\s*\n'
        r'([ \t]*)return\s+jdbc\.queryForList\s*\(\s*sql\s*\)\s*;\s*'
    )

    replacement = (
        r'\1String sql = "SELECT * FROM USERS WHERE NAME = ?";\n'
        r'\2return jdbc.queryForList(sql, name);\n'
    )

    modified, count = pattern.subn(replacement, modified)

    if count == 0:
        return None

    if modified == original:
        return None

    return {
        "file": path,
        "content": modified
    }


# ============================================================
# RAG fallback (currently disabled)
# ============================================================

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
    return None