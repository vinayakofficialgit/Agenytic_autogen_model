print("RUN_AGENT VERSION: ENTERPRISE V2")
#!/usr/bin/env python3
import pathlib
import subprocess
from typing import Dict, Any, List

# ============================================================
# Configuration
# ============================================================

AST_JAR = pathlib.Path("tools/java-ast-fixer/target/java-ast-fixer-1.0.jar")

RULE_MAP = {
    "sql-injection": "SqlInjectionFixer",
    "weak-random": "WeakRandomFixer",
    "md5-usage": "MD5Fixer",
    "command-injection": "CommandInjectionFixer",
}

# ============================================================
# Helpers
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
# Deterministic AST Fix
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
    print(f"→ Target file: {path}")

    if not AST_JAR.exists():
        print("⚠ AST jar not found — deterministic stage skipped")
        return None

    try:
        subprocess.run(
            [
                "java",
                "-jar",
                str(AST_JAR),
                path,
                rule_id
            ],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"⚠ AST engine failed: {e}")
        return None

    modified = _read(path)

    # No change
    if modified == original:
        print("⚠ AST rule applied no changes")
        return None

    # Empty guard
    if len(modified.strip()) == 0:
        print("⚠ AST produced empty file — skipping")
        return None

    # Safety guard (prevent file deletion issue)
    if len(modified) < len(original) * 0.5:
        print("⚠ AST rewrite suspiciously small — skipping")
        return None

    print(f"✓ Resolved by: AST ({rule_id})")

    return {
        "file": path,
        "content": modified
    }

# ============================================================
# Query Builder (Required by run_agent)
# ============================================================

def query_for(item: dict) -> str:
    """
    Required interface for RAG/LLM fallback.
    Even if deterministic succeeds, run_agent expects this to exist.
    """
    rule = (item.get("rule") or "").lower()
    detail = (item.get("detail") or "").lower()
    return f"Secure Java remediation for {rule} {detail}"


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

# #!/usr/bin/env python3
# import pathlib
# import subprocess
# from typing import Dict, Any, List


# # ============================================================
# # AST Rule Mapping
# # ============================================================

# RULE_MAP = {
#     "sql-injection": "SqlInjectionFixer",
#     "weak-random": "WeakRandomFixer",
#     "md5-usage": "MD5Fixer",
#     "command-injection": "CommandInjectionFixer",
# }


# def query_for(item: dict) -> str:
#     return "secure java coding example remediation"


# # ============================================================
# # Path Helpers
# # ============================================================

# def _resolve_full_path(path: str) -> str:
#     p = pathlib.Path(path)

#     if p.exists():
#         return str(p)

#     prefixed = pathlib.Path("java-pilot-app") / p
#     if prefixed.exists():
#         return str(prefixed)

#     return ""


# def _read(path: str) -> str:
#     p = pathlib.Path(path)
#     if not p.exists():
#         return ""
#     return p.read_text(encoding="utf-8", errors="ignore")


# # ============================================================
# # AST Deterministic Fix
# # ============================================================

# def try_deterministic(item: dict) -> Dict[str, str] | None:
#     raw_path = item.get("file", "")
#     if not raw_path.endswith(".java"):
#         return None

#     path = _resolve_full_path(raw_path)
#     if not path:
#         print(f"⚠ Java file not found: {raw_path}")
#         return None

#     original = _read(path)
#     if not original.strip():
#         return None

#     rule_id = _map_rule(item)
#     if not rule_id:
#         return None

#     print(f"→ AST Rule Triggered: {rule_id}")

#     try:
#         subprocess.run(
#             [
#                 "java",
#                 "-cp",
#                 "tools/java-ast-fixer/target/java-ast-fixer-1.0.jar",
#                 path,
#                 rule_id
#             ],
#             check=True
#         )
#     except Exception as e:
#         print(f"⚠ AST engine failed: {e}")
#         return None

#     modified = _read(path)

#     if modified == original:
#         print("⚠ AST rule applied no changes")
#         return None

#     if len(modified.strip()) == 0:
#         print("⚠ AST produced empty file — skipping")
#         return None

#     if len(modified) < len(original) * 0.5:
#         print("⚠ AST rewrite suspiciously small — skipping")
#         return None

#     return {
#         "file": path,
#         "content": modified
#     }


# # ============================================================
# # Rule Mapper
# # ============================================================

# def _map_rule(item: dict) -> str | None:
#     rule = (item.get("rule") or "").lower()
#     detail = (item.get("detail") or "").lower()

#     if "sql" in rule or "sql" in detail:
#         return "SqlInjectionFixer"

#     if "random" in rule:
#         return "WeakRandomFixer"

#     if "md5" in rule:
#         return "MD5Fixer"

#     if "command" in rule:
#         return "CommandInjectionFixer"

#     return None


# # ============================================================
# # RAG Fallback (Optional)
# # ============================================================

# def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
#     return None