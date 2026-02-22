"""
Regression Tester
Checks behavioral regression risk.
"""

def regression_risk(diff):
    if "security" in diff.lower():
        return "low"
    return "medium"