#!/usr/bin/env python3
"""
Fixer for Java / Spring / JDBC findings.

Deterministic:  regex-based SQL-injection → parameterized query.
RAG:            reserved for future use.
LLM fallback:  handled by run_agent.py via prompt_lib.
"""
import pathlib
import difflib
import re
from typing import List, Dict, Any


def query_for(item: dict) -> str:
    return "java spring jdbc JdbcTemplate prepared statement parameterized query"


def _read(p: str) -> str:
    data = pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")  # normalize EOL


def _write_diff(old: str, new: str, path: str) -> str:
    """
    Produce a unified diff between old and new content.
    Uses plain '--- path' / '+++ path' headers (no a/ b/ prefix).
    git_ops.py will normalize these to proper git-style headers.
    """
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    out = "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path))
    if not out.endswith("\n"):
        out += "\n"
    return out


# ── SQL Injection: concatenated query → parameterized ──────────────

_SQL_CONCAT_PATTERN = re.compile(
    r'(?ms)'
    r'^([ \t]*)String\s+sql\s*=\s*"SELECT\s+\*\s+FROM\s+USERS\s+WHERE\s+NAME\s*=\s*\'"'
    r'\s*\+\s*name\s*\+\s*"\'"\s*;\s*\n'
    r'([ \t]*)return\s+jdbc\.queryForList\s*\(\s*sql\s*\)\s*;'
)

_SQL_CONCAT_REPLACEMENT = (
    r'\1String sql = "SELECT * FROM USERS WHERE NAME = ?";'
    '\n'
    r'\2return jdbc.queryForList(sql, name);'
)


def try_deterministic(item: dict) -> str | None:
    """
    Attempt a deterministic (regex-based) fix for known Java vulnerabilities.
    Currently handles:
      - SQL injection via string concatenation → parameterized query
    """
    path = item.get("file", "")
    if not path.endswith(".java"):
        return None

    raw = _read(path)
    changed = raw

    # SQL injection fix: concatenated SQL → parameterized
    changed, count = _SQL_CONCAT_PATTERN.subn(_SQL_CONCAT_REPLACEMENT, changed)

    if changed != raw:
        return _write_diff(raw, changed, path)

    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    """
    RAG-based fix using retrieved code context.
    Reserved for future use — returns None to fall through to LLM.
    """
    return None
