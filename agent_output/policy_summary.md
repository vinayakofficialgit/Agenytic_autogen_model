# Policy Gate Summary

**Status:** ❌ FAIL
**Reason:** Found high (>= high) from semgrep at app/main.py:12

## Stats
- Total: 1
- Worst severity: high
- Weighted score: 3

### By Severity
  - 🔴 critical: 0
  - 🟠 high: 1
  - 🟡 medium: 0
  - 🟢 low: 0

### By Category
  - code: 1
  - infra: 0
  - image: 0
  - policy: 0
  - secrets: 0
  - webapp: 0

### By Tool
  - semgrep: 1

## Violations
1. 🟠 **[HIGH]** semgrep @ `app/main.py:12` (id: `TEST001`)
   - Hardcoded password detected
