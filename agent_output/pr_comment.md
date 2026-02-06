## 🛡️ Security Scan — ❌ Fail

**Reason:** Found high (>= high) from semgrep at app/main.py:12

### Summary
- **Total findings:** 3
- **Worst severity:** high
- 🔴 Critical: 0 | 🟠 High: 2 | 🟡 Medium: 1 | 🟢 Low: 0

### Top Recommendations

**Semgrep:**
- [HIGH] 🔄 `app/main.py:12` (TEST001)

**Trivy-FS:**
- [HIGH] 🔄 `Dockerfile` (CVE-2025-0001)
- [MEDIUM] 🔄 `Dockerfile` (AVD-TRIVY-0001)

---
_See `llm_recommendations_summary.md` for full details._

_🔄 = Fallback suggestion (3 total) - LLM was unavailable_