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
    # Capture and reuse indentation so braces remain intact.
    pattern = re.compile(
        r'(?ms)^([ \t]*)String\s+sql\s*=\s*"SELECT\s+\*\s+FROM\s+USERS\s+WHERE\s+NAME\s*=\s*\'"\s*\+\s*name\s*\+\s*"\'";\s*\n'
        r'([ \t]*)return\s+jdbc\.queryForList\s*\(\s*sql\s*\)\s*;\s*'
    )
    replacement = (
        r'\1String sql = "SELECT * FROM USERS WHERE NAME = ?";\n'
        r'\2return jdbc.queryForList(sql, name);\n'
    )
    changed, _ = pattern.subn(replacement, changed)

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    return None