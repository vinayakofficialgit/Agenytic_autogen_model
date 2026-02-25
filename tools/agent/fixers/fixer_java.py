#!/usr/bin/env python3
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
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    out = "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path))
    if not out.endswith("\n"):
        out += "\n"
    return out


def try_deterministic(item: dict) -> str | None:
    path = item.get("file", "")
    if not path.endswith(".java"):
        return None

    raw = _read(path)
    changed = raw

    # Replace concatenated SQL + subsequent return with parameterized version.
    # Matches: String sql = "... '" + name + "'";  <newline>  return jdbc.queryForList(sql);
    pattern = re.compile(
        r'(?ms)'
        r'(String\s+sql\s*=\s*"SELECT\s+\*\s+FROM\s+USERS\s+WHERE\s+NAME\s*=\s*\'"\s*\+\s*name\s*\+\s*"\'";\s*)'
        r'(return\s+jdbc\.queryForList\s*\(\s*sql\s*\)\s*;\s*)'
    )
    replacement = (
        'String sql = "SELECT * FROM USERS WHERE NAME = ?";\n'
        '        return jdbc.queryForList(sql, name);\n'
    )
    changed, n = pattern.subn(replacement, changed)

    if n == 0:
        # Fallback: only swap the SQL and upgrade the return if present
        changed = re.sub(
            r'String\s+sql\s*=\s*"SELECT\s+\*\s+FROM\s+USERS\s+WHERE\s+NAME\s*=\s*\'"\s*\+\s*name\s*\+\s*"\'";',
            'String sql = "SELECT * FROM USERS WHERE NAME = ?";',
            changed,
        )
        changed = re.sub(
            r'return\s+jdbc\.queryForList\s*\(\s*sql\s*\)\s*;',
            'return jdbc.queryForList(sql, name);',
            changed,
        )

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    return None