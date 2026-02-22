"""
Human Gate
Determines need for human approval.
"""

def requires_human(confidence):
    if confidence < 70:
        return True
    return False