import pathlib, difflib, re
from typing import List, Dict, Any

def query_for(item: dict) -> str:
    return "java spring jdbc JdbcTemplate prepared statement parameterized query"

def _read(p: str) -> str:
    return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")

def _write_diff(old: str, new: str, path: str) -> str:
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path))

def try_deterministic(item: dict) -> str|None:
    path = item.get("file","")
    if not path.endswith(".java"): return None
    raw = _read(path)
    changed = raw

    # Very targeted SQL concat → parameterized pattern:
    changed = re.sub(
        r'String\s+sql\s*=\s*"SELECT \* FROM USERS WHERE NAME = \'" \+ ([a-zA-Z_][a-zA-Z0-9_]*) \+ "\'"',
        r'String sql = "SELECT * FROM USERS WHERE NAME = ?";\n    return jdbc.queryForList(sql, \\1);',
        changed
    )

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None

def try_rag_style(item: dict, topk: List[Dict[str,Any]]) -> str|None:
    # If RAG snippet shows findByName(?) style, we could mirror but deterministic already covers our demo case.
    return None