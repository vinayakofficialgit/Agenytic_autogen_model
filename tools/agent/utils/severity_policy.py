#!/usr/bin/env python3
"""
Centralized Severity Policy Engine
Supports:
- threshold mode (>=)
- exact mode (==)
"""

import os

SEV_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

MIN_SEVERITY = os.getenv("MIN_SEVERITY", "HIGH").upper()
SEVERITY_MODE = os.getenv("SEVERITY_MODE", "threshold").lower()

def want(sev: str) -> bool:
    sev = (sev or "").upper()

    if SEVERITY_MODE == "exact":
        return sev == MIN_SEVERITY

    # default = threshold
    return SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(MIN_SEVERITY, 0)



# import os

# SEV_ORDER = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}

# MIN_SEVERITY = os.getenv("MIN_SEVERITY", "HIGH").upper()
# SEVERITY_MODE = os.getenv("SEVERITY_MODE", "threshold").lower()

# def want(sev: str):
#     sev = (sev or "").upper()

#     if SEVERITY_MODE == "exact":
#         return sev == MIN_SEVERITY

#     return SEV_ORDER.get(sev,0) >= SEV_ORDER.get(MIN_SEVERITY,0)


