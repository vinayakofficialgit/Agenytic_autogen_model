#!/usr/bin/env python3
"""
Fixer for Java / Spring / JDBC findings.

Deterministic:  regex-based SQL-injection → parameterized query.
RAG:            reserved for future use.
LLM fallback:   handled by run_agent.py via prompt_lib.
"""
import pathlib
import difflib
import re
import os
from typing import List, Dict, Any


def query_for(item: dict) -> str:
    return "java spring jdbc JdbcTemplate prepared statement parameterized query"


def _read(p: str) -> str:
    """Read a file, trying both raw path and repo-root-relative path."""
    path = pathlib.Path(p)
    if path.is_file():
        print(f"  [fixer-java] Reading file: {path}")
        data = path.read_text(encoding="utf-8", errors="ignore")
        return data.replace("\r\n", "\n").replace("\r", "\n")

    # If not found, try from repo root (in case CWD is different)
    # Common CI patterns: the file might be at a different relative path
    alt_paths = [
        pathlib.Path(p),
        pathlib.Path("java-pilot-app") / p if not p.startswith("java-pilot-app") else None,
    ]
    for alt in alt_paths:
        if alt and alt.is_file():
            print(f"  [fixer-java] Reading file (alt path): {alt}")
            data = alt.read_text(encoding="utf-8", errors="ignore")
            return data.replace("\r\n", "\n").replace("\r", "\n")

    raise FileNotFoundError(f"Cannot find file: {p} (cwd={os.getcwd()})")


def _write_diff(old: str, new: str, path: str) -> str:
    """
    Produce a unified diff between old and new content.
    Uses plain '--- path' / '+++ path' headers (no a/ b/ prefix).
    git_ops.py will normalize these to proper git-style headers.
    """
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    out = "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path))
    if out and not out.endswith("\n"):
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
    print(f"  [fixer-java] try_deterministic called for: {path}")

    if not path.endswith(".java"):
        print(f"  [fixer-java] Skipping non-Java file: {path}")
        return None

    try:
        raw = _read(path)
    except FileNotFoundError as e:
        print(f"  [fixer-java] ERROR: {e}")
        return None

    print(f"  [fixer-java] File read OK, {len(raw)} chars, {raw.count(chr(10))} lines")

    changed = raw

    # SQL injection fix: concatenated SQL → parameterized
    changed, count = _SQL_CONCAT_PATTERN.subn(_SQL_CONCAT_REPLACEMENT, changed)
    print(f"  [fixer-java] SQL injection regex: {count} replacement(s) made")

    if count > 0 and changed != raw:
        diff = _write_diff(raw, changed, path)
        print(f"  [fixer-java] Diff generated: {len(diff)} chars")
        if diff:
            # Show what the diff looks like
            for line in diff.split("\n")[:15]:
                print(f"    DIFF> {line}")
            if diff.count("\n") > 15:
                print(f"    DIFF> ... ({diff.count(chr(10))} total lines)")
        return diff
    else:
        print(f"  [fixer-java] No changes made — regex did not match file content")
        # Debug: show what's around the SQL line to help diagnose
        for i, line in enumerate(raw.split("\n")):
            if "SELECT" in line or "queryForList" in line:
                print(f"    DEBUG line {i+1}: [{repr(line)}]")
        return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    """
    RAG-based fix using retrieved code context.
    Reserved for future use — returns None to fall through to LLM.
    """
    return None
