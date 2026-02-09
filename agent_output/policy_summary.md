# Policy Gate Summary

**Status:** ❌ FAIL
**Reason:** Found high (>= high) from semgrep at app/main.py:12

## Stats
- Total: 3
- Worst severity: high
- Weighted score: 8

### By Severity
  - 🔴 critical: 0
  - 🟠 high: 2
  - 🟡 medium: 1
  - 🟢 low: 0

### By Category
  - code: 1
  - infra: 2
  - image: 0
  - policy: 0
  - secrets: 0
  - webapp: 0

### By Tool
  - trivy_fs: 2
  - semgrep: 1

## Violations
1. 🟠 **[HIGH]** semgrep @ `app/main.py:12` (id: `TEST001`)
   - Hardcoded password detected
2. 🟠 **[HIGH]** trivy_fs @ `Dockerfile` (id: `CVE-2025-0001`)
   - Example OpenSSL issue
