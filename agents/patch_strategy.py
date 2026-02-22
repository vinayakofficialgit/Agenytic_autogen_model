"""
Patch Strategy Engine
Decides how to fix vulnerability safely.
"""

def choose_patch_strategy(finding: dict) -> str:
    title = str(finding.get("title", "")).lower()

    if "sql injection" in title:
        return "ast"

    if "command injection" in title:
        return "ast"

    if "xss" in title:
        return "template"

    if finding.get("severity") in ["high", "critical"]:
        return "llm"

    return "suggestion"