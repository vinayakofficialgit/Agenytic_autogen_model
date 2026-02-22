"""
Patch Confidence Engine
Scores trust level of autofix patch.
"""

def compute_confidence(strategy, compile_ok, test_ok):
    score = 0

    if strategy == "ast":
        score += 40
    if strategy == "deterministic":
        score += 35
    if strategy == "llm":
        score += 15

    if compile_ok:
        score += 20
    if test_ok:
        score += 20

    return score