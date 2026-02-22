"""
PR Enricher
Adds security explanation to PR.
"""

def generate_pr_comment(finding, confidence):
    return f"""
Vulnerability: {finding.get('title')}
File: {finding.get('file')}
Confidence: {confidence}
"""