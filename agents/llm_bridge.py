


# # llm_bridge.py - Enhanced Ollama Bridge with Quiet Mode
# """
# Enhanced LLM Bridge for DevSecOps Agentic AI Pipeline

# Key Features:
# - Quiet mode by default (set LLM_VERBOSE=1 for debug output)
# - Built-in fallback suggestions for common security issues
# - Better error capture for diagnostics
# - Health check without verbose output
# """

# import os
# import requests
# import json
# import time
# from typing import List, Dict, Any, Optional

# __all__ = [
#     "assistant_factory",
#     "ollama_chat",
#     "assert_ollama_available",
#     "check_ollama_health",
#     "get_fallback_suggestion",
#     "OllamaHealthError",
# ]


# # =============================================================================
# # CONFIGURATION
# # =============================================================================

# def _is_verbose() -> bool:
#     """Check if verbose mode is enabled."""
#     return os.getenv("LLM_VERBOSE", "0") == "1"


# def _log(msg: str):
#     """Log message only in verbose mode."""
#     if _is_verbose():
#         print(msg)


# # =============================================================================
# # FALLBACK SECURITY SUGGESTIONS
# # =============================================================================

# FALLBACK_SUGGESTIONS = {
#     "hardcoded-password": """
# **Risk**: Hardcoded passwords expose credentials in source code, making them vulnerable to leakage.

# **Remediation**:
# 1. Remove the hardcoded password immediately
# 2. Use environment variables: `os.environ.get('DB_PASSWORD')`
# 3. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
# 4. Add the file to `.gitignore` if it contains local config

# **Example Fix**:
# ```python
# # Before (INSECURE)
# password = "mysecretpassword"

# # After (SECURE)
# import os
# password = os.environ.get('DB_PASSWORD')
# if not password:
#     raise ValueError("DB_PASSWORD environment variable not set")
# ```

# **Best Practices**:
# - Never commit secrets to version control
# - Use .env files for local development (add to .gitignore)
# - Rotate credentials regularly
# - Use different credentials for dev/staging/prod
# """,
    
#     "sql-injection": """
# **Risk**: SQL injection allows attackers to execute arbitrary SQL commands.

# **Remediation**:
# 1. Use parameterized queries (prepared statements)
# 2. Never concatenate user input into SQL strings
# 3. Use an ORM like SQLAlchemy with proper escaping

# **Example Fix**:
# ```python
# # Before (VULNERABLE)
# query = f"SELECT * FROM users WHERE id = {user_id}"

# # After (SECURE)
# query = "SELECT * FROM users WHERE id = ?"
# cursor.execute(query, (user_id,))
# ```

# **Best Practices**:
# - Always use parameterized queries
# - Validate and sanitize all user inputs
# - Use ORMs with built-in SQL injection protection
# - Implement least-privilege database access
# """,

#     "xss": """
# **Risk**: Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.

# **Remediation**:
# 1. Always escape/encode output displayed in HTML
# 2. Use Content Security Policy (CSP) headers
# 3. Use framework auto-escaping (React, Django templates, etc.)
# 4. Validate and sanitize all user inputs

# **Best Practices**:
# - Use `textContent` instead of `innerHTML` when possible
# - Implement strict CSP headers
# - Use HTTP-only cookies for sensitive data
# - Sanitize HTML input with libraries like DOMPurify
# """,

#     "cve": """
# **Risk**: Known vulnerability (CVE) in a dependency or base image.

# **Remediation**:
# 1. Update the affected package to a patched version
# 2. If using Docker, update the base image: `docker pull <image>:latest`
# 3. Run `pip install --upgrade <package>` or `npm update <package>`
# 4. If no patch available, consider alternative packages or mitigating controls

# **Commands**:
# ```bash
# # Update Docker base image
# docker pull python:3.12-slim

# # Update Python packages
# pip install --upgrade <vulnerable-package>

# # Update npm packages  
# npm update <vulnerable-package>

# # Check for outdated packages
# pip list --outdated
# npm outdated
# ```

# **Best Practices**:
# - Enable automated dependency updates (Dependabot, Renovate)
# - Pin versions in production, but review updates regularly
# - Subscribe to security advisories for critical dependencies
# """,

#     "dockerfile-root": """
# **Risk**: Running containers as root increases attack surface and potential damage from breaches.

# **Remediation**:
# 1. Add a non-root user in Dockerfile
# 2. Switch to that user before CMD/ENTRYPOINT
# 3. Ensure file permissions allow the non-root user to operate

# **Example Fix**:
# ```dockerfile
# # Create non-root user
# RUN adduser --disabled-password --gecos '' appuser

# # Set ownership of app files
# COPY --chown=appuser:appuser . /app

# # Switch to non-root user
# USER appuser

# # Run application
# CMD ["python", "app.py"]
# ```

# **Best Practices**:
# - Never run production containers as root
# - Use minimal base images (alpine, distroless)
# - Drop all unnecessary capabilities
# - Set read-only root filesystem when possible
# """,

#     "dockerfile-add": """
# **Risk**: ADD instruction can have unexpected behavior with URLs and archives.

# **Remediation**: Use COPY instead of ADD for local files.

# **Example Fix**:
# ```dockerfile
# # Before (risky)
# ADD ./app /app

# # After (safe)
# COPY ./app /app
# ```

# **When to use ADD**:
# - Only when you need auto-extraction of tar archives
# - Only when you need to download from URLs (prefer curl/wget for better control)
# """,

#     "open-cidr": """
# **Risk**: 0.0.0.0/0 allows access from any IP address worldwide, exposing services to the internet.

# **Remediation**:
# 1. Restrict to specific IP ranges or VPC CIDRs
# 2. Use security groups with least-privilege access
# 3. Implement VPN or bastion host for administrative access

# **Example Fix**:
# ```hcl
# # Before (INSECURE)
# cidr_blocks = ["0.0.0.0/0"]

# # After (SECURE) - Internal network only
# cidr_blocks = ["10.0.0.0/8"]

# # Or specific office IP
# cidr_blocks = ["203.0.113.0/24"]
# ```

# **Best Practices**:
# - Never expose management ports (SSH, RDP) to 0.0.0.0/0
# - Use VPN or AWS Systems Manager for admin access
# - Implement network segmentation
# - Use private subnets for internal services
# """,

#     "k8s-privileged": """
# **Risk**: Privileged containers have full host access, defeating container isolation.

# **Remediation**:
# 1. Set `privileged: false` in securityContext
# 2. Use specific capabilities instead of full privileges
# 3. Enable `runAsNonRoot: true`
# 4. Drop all capabilities and add only what's needed

# **Example Fix**:
# ```yaml
# securityContext:
#   privileged: false
#   runAsNonRoot: true
#   runAsUser: 1000
#   allowPrivilegeEscalation: false
#   capabilities:
#     drop:
#       - ALL
#     add:
#       - NET_BIND_SERVICE  # Only if needed
# ```

# **Best Practices**:
# - Use Pod Security Standards/Policies
# - Implement OPA Gatekeeper for policy enforcement
# - Scan manifests with tools like kubesec, kube-linter
# """,

#     "k8s-no-limits": """
# **Risk**: Containers without resource limits can starve other workloads and cause node instability.

# **Remediation**: Set CPU and memory limits for all containers.

# **Example Fix**:
# ```yaml
# resources:
#   limits:
#     cpu: "500m"
#     memory: "256Mi"
#   requests:
#     cpu: "100m"
#     memory: "128Mi"
# ```

# **Best Practices**:
# - Always set both requests and limits
# - Use LimitRange for namespace defaults
# - Monitor actual usage and adjust accordingly
# - Implement ResourceQuotas per namespace
# """,

#     "exposed-secret": """
# **Risk**: Secrets in code/config can be leaked through version control.

# **Remediation**:
# 1. Remove the secret immediately
# 2. Rotate the compromised credential NOW
# 3. Use environment variables or secrets manager
# 4. Add patterns to `.gitignore`

# **Immediate Actions**:
# ```bash
# # Remove secret from Git history (if already committed)
# git filter-branch --force --index-filter \\
#   "git rm --cached --ignore-unmatch <file-with-secret>" \\
#   --prune-empty --tag-name-filter cat -- --all

# # Or use BFG Repo-Cleaner (faster)
# bfg --delete-files <file-with-secret>
# ```

# **Best Practices**:
# - Use git-secrets or pre-commit hooks
# - Implement secret scanning in CI/CD
# - Use HashiCorp Vault or cloud secret managers
# - Rotate secrets regularly
# """,

#     "generic-high": """
# **Risk**: High severity security finding detected.

# **General Remediation Steps**:
# 1. Review the specific finding details
# 2. Understand the attack vector
# 3. Apply the principle of least privilege
# 4. Update vulnerable components
# 5. Add security tests to prevent regression

# **Priority Actions**:
# - Address immediately - high severity findings should be fixed before deployment
# - Implement compensating controls if immediate fix isn't possible
# - Document any accepted risks with justification
# """,

#     "generic-medium": """
# **Risk**: Medium severity security finding detected.

# **General Remediation Steps**:
# 1. Evaluate the risk in your specific context
# 2. Plan remediation based on effort vs impact
# 3. Consider defense-in-depth mitigations
# 4. Document accepted risks if not immediately fixable

# **Timeline**:
# - Should be addressed within the current sprint/release
# - May be acceptable in dev/staging with compensating controls
# """,
# }


# def get_fallback_suggestion(
#     tool: str,
#     rule_id: str = "",
#     severity: str = "",
#     message: str = "",
# ) -> str:
#     """Get a pre-built fallback suggestion when LLM is unavailable."""
#     rule_lower = (rule_id or "").lower()
#     msg_lower = (message or "").lower()
#     sev_lower = (severity or "").lower()
#     tool_lower = (tool or "").lower()
    
#     # Keyword matching
#     keyword_map = {
#         "hardcoded": "hardcoded-password",
#         "password": "hardcoded-password",
#         "credential": "hardcoded-password",
#         "secret": "exposed-secret",
#         "api_key": "exposed-secret",
#         "apikey": "exposed-secret",
#         "token": "exposed-secret",
#         "sql": "sql-injection",
#         "injection": "sql-injection",
#         "xss": "xss",
#         "cross-site": "xss",
#         "cve": "cve",
#         "vulnerability": "cve",
#         "root": "dockerfile-root",
#         "nonroot": "dockerfile-root",
#         "user": "dockerfile-root",
#         "add": "dockerfile-add",
#         "cidr": "open-cidr",
#         "0.0.0.0": "open-cidr",
#         "privileged": "k8s-privileged",
#         "limit": "k8s-no-limits",
#         "resource": "k8s-no-limits",
#     }
    
#     for keyword, suggestion_key in keyword_map.items():
#         if keyword in rule_lower or keyword in msg_lower:
#             return FALLBACK_SUGGESTIONS.get(suggestion_key, "")
    
#     # Tool-specific defaults
#     if tool_lower in ("trivy", "trivy-fs", "trivy_fs", "trivy-image"):
#         return FALLBACK_SUGGESTIONS.get("cve", "")
    
#     if tool_lower == "gitleaks":
#         return FALLBACK_SUGGESTIONS.get("exposed-secret", "")
    
#     if tool_lower == "tfsec":
#         return FALLBACK_SUGGESTIONS.get("open-cidr", "")
    
#     # Severity-based fallback
#     if sev_lower in ("high", "critical"):
#         return FALLBACK_SUGGESTIONS.get("generic-high", "")
    
#     return FALLBACK_SUGGESTIONS.get("generic-medium", "")


# # =============================================================================
# # OLLAMA HEALTH CHECK
# # =============================================================================

# class OllamaHealthError(Exception):
#     """Raised when Ollama is not healthy."""
#     pass


# def check_ollama_health(
#     base_url: Optional[str] = None,
#     model: Optional[str] = None,
#     timeout: float = 10.0,
# ) -> Dict[str, Any]:
#     """Check Ollama server health and model availability."""
#     base_url = (base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
#     model = model or os.getenv("OLLAMA_MODEL", "llama3:latest")
    
#     result = {
#         "healthy": False,
#         "server_reachable": False,
#         "model_available": False,
#         "model_name": model,
#         "available_models": [],
#         "error": None,
#     }
    
#     try:
#         r = requests.get(f"{base_url}/api/tags", timeout=timeout)
#         r.raise_for_status()
#         result["server_reachable"] = True
        
#         data = r.json()
#         models = data.get("models", [])
#         result["available_models"] = [m.get("name", "") for m in models]
        
#         model_base = model.split(":")[0]
#         for m in result["available_models"]:
#             m_base = m.split(":")[0]
#             if m_base == model_base or m == model:
#                 result["model_available"] = True
#                 break
        
#         if result["model_available"]:
#             result["healthy"] = True
#         else:
#             result["error"] = f"Model '{model}' not found"
            
#     except requests.exceptions.ConnectionError:
#         result["error"] = f"Cannot connect to Ollama at {base_url}"
#     except requests.exceptions.Timeout:
#         result["error"] = f"Timeout connecting to Ollama"
#     except Exception as e:
#         result["error"] = str(e)
    
#     return result


# def assert_ollama_available(
#     base_url: Optional[str] = None,
#     model: Optional[str] = None,
#     timeout: float = 10.0,
# ) -> None:
#     """Assert that Ollama is available. Raises OllamaHealthError if not."""
#     health = check_ollama_health(base_url, model, timeout)
#     if not health["healthy"]:
#         raise OllamaHealthError(health.get("error", "Unknown error"))


# # =============================================================================
# # ASSISTANT FACTORY
# # =============================================================================

# def assistant_factory(
#     name: str,
#     system_message: str,
#     temperature: float = 0.2,
#     use_fallback: bool = True,
# ):
#     """Create an Ollama-backed assistant with quiet error handling."""
#     base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
#     model = os.getenv("OLLAMA_MODEL", "llama3:latest")
    
#     connect_t = float(os.getenv("LLM_CONNECT_TIMEOUT", "10"))
#     read_t = float(os.getenv("LLM_READ_TIMEOUT", "600"))
#     num_predict = int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))
#     num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
#     stream_enabled = os.getenv("LLM_STREAM", "1") == "1"
#     max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    
#     session = requests.Session()
    
#     # Log config once (only in verbose mode)
#     _log(
#         f"[llm_bridge] Using Ollama model={model} url={base_url} "
#         f"stream={stream_enabled} timeout={int(connect_t)}/{int(read_t)}s "
#         f"num_predict={num_predict} ctx={num_ctx}"
#     )
    
#     class Assistant:
#         def __init__(self, name: str, system_message: str, temperature: float):
#             self.name = name
#             self.system_message = system_message
#             self.temperature = float(temperature)
#             self._health_checked = False

#         def _extract_context(self, messages: List[Dict[str, str]]) -> Dict[str, str]:
#             """Extract context for fallback matching."""
#             context = {"tool": "", "rule_id": "", "severity": "", "message": ""}
#             for msg in messages:
#                 content = msg.get("content", "").lower()
#                 for tool in ["semgrep", "trivy", "tfsec", "gitleaks", "conftest", "zap"]:
#                     if tool in content:
#                         context["tool"] = tool
#                         break
#                 for sev in ["critical", "high", "medium", "low"]:
#                     if sev in content:
#                         context["severity"] = sev
#                         break
#                 context["message"] = content[:500]
#             return context

#         def chat_completion_fn(self, messages: List[Dict[str, str]]) -> str:
#             """Call Ollama with quiet error handling."""
#             chat_messages = [
#                 {"role": msg.get("role", "user"), "content": msg.get("content", "")}
#                 for msg in messages if msg.get("content")
#             ]
            
#             payload = {
#                 "model": model,
#                 "messages": chat_messages,
#                 "stream": stream_enabled,
#                 "options": {
#                     "temperature": self.temperature,
#                     "num_predict": num_predict,
#                     "num_ctx": num_ctx,
#                 }
#             }
            
#             chat_url = f"{base_url}/api/chat"
#             last_error = None
            
#             for attempt in range(max_retries):
#                 try:
#                     _log(f"[llm_bridge] Attempt {attempt+1}/{max_retries} for agent={self.name}")
                    
#                     if stream_enabled:
#                         acc: List[str] = []
#                         with session.post(chat_url, json=payload, stream=True, timeout=(connect_t, read_t)) as r:
#                             r.raise_for_status()
#                             for line in r.iter_lines():
#                                 if not line:
#                                     continue
#                                 obj = json.loads(line.decode("utf-8"))
#                                 msg = obj.get("message", {})
#                                 if msg.get("content"):
#                                     acc.append(msg["content"])
#                                 if obj.get("done"):
#                                     break
#                         return "".join(acc).strip()
#                     else:
#                         r = session.post(chat_url, json=payload, timeout=(connect_t, read_t))
#                         r.raise_for_status()
#                         obj = r.json()
#                         return obj.get("message", {}).get("content", "").strip()
                
#                 except requests.exceptions.HTTPError as e:
#                     status_code = getattr(e.response, 'status_code', 'unknown')
#                     error_body = ""
#                     try:
#                         error_body = e.response.text[:200] if hasattr(e.response, 'text') else ""
#                     except:
#                         pass
                    
#                     last_error = f"HTTP {status_code}: {error_body or str(e)}"
#                     _log(f"[llm_bridge] HTTP error on attempt {attempt+1}/{max_retries}: {last_error}")
                    
#                     if status_code == 500:
#                         _log(f"[llm_bridge] 500 Error - Possible causes:")
#                         _log(f"  • Model '{model}' may not be fully loaded")
#                         _log(f"  • Try: `ollama pull {model}` to re-download")
#                         _log(f"  • Check Ollama logs: `journalctl -u ollama` or Docker logs")
                    
#                     if attempt < max_retries - 1:
#                         time.sleep(2 * (attempt + 1))
                
#                 except requests.exceptions.Timeout:
#                     last_error = "Request timed out"
#                     _log(f"[llm_bridge] Timeout on attempt {attempt+1}/{max_retries}")
#                     if attempt < max_retries - 1:
#                         time.sleep(2 * (attempt + 1))
                
#                 except Exception as e:
#                     last_error = str(e)
#                     _log(f"[llm_bridge] Error on attempt {attempt+1}/{max_retries}: {e}")
#                     if attempt < max_retries - 1:
#                         time.sleep(1.5 * (attempt + 1))
            
#             # All retries failed - use fallback
#             if use_fallback:
#                 context = self._extract_context(messages)
#                 fallback = get_fallback_suggestion(
#                     tool=context["tool"],
#                     rule_id=context["rule_id"],
#                     severity=context["severity"],
#                     message=context["message"],
#                 )
#                 if fallback:
#                     _log(f"[llm_bridge] Using fallback suggestion for agent={self.name}")
#                     return f"[Fallback - LLM unavailable]\n\n{fallback}"
            
#             raise RuntimeError(f"Ollama error after {max_retries} attempts: {last_error}")

#     return Assistant(name, system_message, temperature)


# # =============================================================================
# # SIMPLE CHAT FUNCTION
# # =============================================================================

# def ollama_chat(
#     system: str,
#     user: str,
#     *,
#     model: Optional[str] = None,
#     temperature: float = 0.2,
#     num_predict: Optional[int] = None,
#     num_ctx: Optional[int] = None,
#     use_fallback: bool = True,
# ) -> str:
#     """Simple wrapper for single-turn Ollama chat."""
#     base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
#     model = model or os.getenv("OLLAMA_MODEL", "llama3:latest")
#     num_ctx = num_ctx or int(os.getenv("OLLAMA_NUM_CTX", "8192"))
#     num_predict = num_predict or int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))
    
#     payload = {
#         "model": model,
#         "stream": False,
#         "messages": [
#             {"role": "system", "content": system},
#             {"role": "user", "content": user},
#         ],
#         "options": {
#             "temperature": float(temperature),
#             "num_predict": int(num_predict),
#             "num_ctx": int(num_ctx),
#         },
#     }

#     try:
#         r = requests.post(
#             f"{base_url}/api/chat", 
#             json=payload, 
#             timeout=(10, 600)
#         )
#         r.raise_for_status()
#         return r.json().get("message", {}).get("content", "").strip()
#     except Exception as e:
#         _log(f"[llm_bridge] ollama_chat error: {e}")
#         if use_fallback:
#             fallback = get_fallback_suggestion(tool="", severity="medium", message=user[:200])
#             if fallback:
#                 return f"[Fallback - LLM unavailable]\n\n{fallback}"
#         raise


# # =============================================================================
# # CLI DIAGNOSTICS
# # =============================================================================

# if __name__ == "__main__":
#     import sys
#     os.environ["LLM_VERBOSE"] = "1"  # Enable verbose for diagnostics
    
#     print("=" * 60)
#     print("Ollama LLM Bridge Diagnostics")
#     print("=" * 60)
    
#     print(f"\nConfiguration:")
#     print(f"  OLLAMA_URL: {os.getenv('OLLAMA_URL', 'http://localhost:11434')}")
#     print(f"  OLLAMA_MODEL: {os.getenv('OLLAMA_MODEL', 'llama3:latest')}")
    
#     print(f"\nHealth Check:")
#     health = check_ollama_health()
#     print(f"  Server reachable: {health['server_reachable']}")
#     print(f"  Model available: {health['model_available']}")
#     if health['error']:
#         print(f"  Error: {health['error']}")
    
#     if health['healthy']:
#         print(f"\nChat Test:")
#         try:
#             response = ollama_chat(
#                 system="You are a helpful assistant.",
#                 user="Say 'OK' to confirm you're working.",
#                 use_fallback=False,
#             )
#             print(f"  Response: {response[:50]}...")
#             print(f"  ✅ Chat working!")
#         except Exception as e:
#             print(f"  ❌ Chat failed: {e}")
    
#     print("\n" + "=" * 60)
#     sys.exit(0 if health['healthy'] else 1)














# llm_bridge.py - Enhanced with Concise Dynamic Suggestions
"""
LLM Bridge with concise, context-specific fallback suggestions.
No generic advice - everything is based on the actual finding.
"""

import os
import requests
import json
import time
from typing import List, Dict, Any, Optional

__all__ = [
    "assistant_factory",
    "ollama_chat",
    "assert_ollama_available",
    "check_ollama_health",
    "get_fallback_suggestion",
    "OllamaHealthError",
]


def _is_verbose() -> bool:
    return os.getenv("LLM_VERBOSE", "0") == "1"


def _log(msg: str):
    if _is_verbose():
        print(msg)


# =============================================================================
# CONCISE FALLBACK SUGGESTIONS - Specific to finding type
# =============================================================================

def get_fallback_suggestion(
    tool: str,
    rule_id: str = "",
    severity: str = "",
    message: str = "",
    file_path: str = "",
    line: str = "",
) -> str:
    """
    Generate CONCISE, context-specific suggestion based on actual finding.
    No generic advice - returns specific fix for the issue type.
    """
    rule_lower = (rule_id or "").lower()
    msg_lower = (message or "").lower()
    tool_lower = (tool or "").lower()
    loc = f"{file_path}:{line}" if file_path and line else file_path or "the affected file"
    
    # Hardcoded credentials
    if any(k in rule_lower or k in msg_lower for k in ["password", "hardcoded", "credential", "secret"]):
        return f"""**Issue**: Hardcoded credential in {loc}

**Fix**:
```python
# Replace hardcoded value with:
import os
value = os.environ.get('SECRET_NAME')
```

**Action**: Add the secret to your .env file and ensure .env is in .gitignore"""

    # SQL Injection
    if any(k in rule_lower or k in msg_lower for k in ["sql", "injection"]):
        return f"""**Issue**: SQL injection risk in {loc}

**Fix**:
```python
# Use parameterized query:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Action**: Never concatenate user input into SQL strings"""

    # Command Injection / Subprocess
    if any(k in rule_lower or k in msg_lower for k in ["subprocess", "shell", "command", "exec"]):
        return f"""**Issue**: Command injection risk in {loc}

**Fix**:
```python
# Use shell=False and pass args as list:
subprocess.run(['cmd', 'arg1', 'arg2'], shell=False)
```"""

    # XSS
    if any(k in rule_lower or k in msg_lower for k in ["xss", "cross-site"]):
        return f"""**Issue**: XSS vulnerability in {loc}

**Fix**: Escape all user input before rendering in HTML.
Use framework's built-in escaping or sanitize with a library."""

    # CVE / Vulnerability
    if "cve" in rule_lower or "cve" in msg_lower or tool_lower in ["trivy", "trivy-fs", "trivy_fs"]:
        cve_id = rule_id if "CVE" in rule_id.upper() else "the vulnerability"
        return f"""**Issue**: {cve_id} in {loc}

**Fix**:
```bash
# Update the affected package:
pip install --upgrade <package-name>
# Or update Docker base image:
docker pull <image>:latest
```

**Action**: Check if a patched version is available"""

    # Docker root user
    if any(k in rule_lower or k in msg_lower for k in ["root", "user", "nonroot"]):
        return f"""**Issue**: Container runs as root in {loc}

**Fix**: Add to Dockerfile:
```dockerfile
RUN adduser --disabled-password appuser
USER appuser
```"""

    # Docker ADD vs COPY
    if "add" in rule_lower and tool_lower in ["trivy", "trivy-fs", "conftest"]:
        return f"""**Issue**: Using ADD instead of COPY in {loc}

**Fix**: Replace `ADD` with `COPY` for local files"""

    # Open CIDR / Network
    if any(k in rule_lower or k in msg_lower for k in ["cidr", "0.0.0.0", "ingress", "public"]):
        return f"""**Issue**: Open network access (0.0.0.0/0) in {loc}

**Fix**:
```hcl
# Restrict to specific CIDR:
cidr_blocks = ["10.0.0.0/8"]  # or your VPC CIDR
```"""

    # S3 / Storage encryption
    if any(k in rule_lower or k in msg_lower for k in ["encrypt", "s3", "bucket"]):
        return f"""**Issue**: Missing encryption in {loc}

**Fix**: Enable encryption for the resource"""

    # Kubernetes privileged
    if "privileged" in rule_lower or "privileged" in msg_lower:
        return f"""**Issue**: Privileged container in {loc}

**Fix**:
```yaml
securityContext:
  privileged: false
  runAsNonRoot: true
```"""

    # Kubernetes resource limits
    if any(k in rule_lower or k in msg_lower for k in ["limit", "resource", "memory", "cpu"]):
        return f"""**Issue**: Missing resource limits in {loc}

**Fix**:
```yaml
resources:
  limits:
    cpu: "500m"
    memory: "256Mi"
```"""

    # Exposed secrets (gitleaks)
    if tool_lower == "gitleaks" or "secret" in tool_lower:
        return f"""**Issue**: Exposed secret in {loc}

**URGENT Actions**:
1. IMMEDIATELY rotate/revoke this credential
2. Remove from code and use environment variable
3. Add to .gitignore to prevent future commits"""

    # Generic high severity
    if severity.lower() in ["high", "critical"]:
        return f"""**Issue**: {severity.upper()} severity finding in {loc}

**Action**: Review and fix the security issue at the specified location.
This should be addressed before deployment."""

    # Generic medium/low
    return f"""**Issue**: Security finding in {loc}

**Action**: Review the finding and apply appropriate fix."""


# =============================================================================
# OLLAMA HEALTH CHECK
# =============================================================================

class OllamaHealthError(Exception):
    pass


def check_ollama_health(
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Check Ollama server health."""
    base_url = (base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
    model = model or os.getenv("OLLAMA_MODEL", "llama3:latest")
    
    result = {
        "healthy": False,
        "server_reachable": False,
        "model_available": False,
        "model_name": model,
        "available_models": [],
        "error": None,
    }
    
    try:
        r = requests.get(f"{base_url}/api/tags", timeout=timeout)
        r.raise_for_status()
        result["server_reachable"] = True
        
        data = r.json()
        models = data.get("models", [])
        result["available_models"] = [m.get("name", "") for m in models]
        
        model_base = model.split(":")[0]
        for m in result["available_models"]:
            if m.split(":")[0] == model_base or m == model:
                result["model_available"] = True
                break
        
        result["healthy"] = result["model_available"]
        if not result["model_available"]:
            result["error"] = f"Model '{model}' not found"
            
    except requests.exceptions.ConnectionError:
        result["error"] = f"Cannot connect to Ollama at {base_url}"
    except requests.exceptions.Timeout:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def assert_ollama_available(base_url: Optional[str] = None, model: Optional[str] = None, timeout: float = 10.0):
    health = check_ollama_health(base_url, model, timeout)
    if not health["healthy"]:
        raise OllamaHealthError(health.get("error", "Unknown error"))


# =============================================================================
# ASSISTANT FACTORY
# =============================================================================

def assistant_factory(
    name: str,
    system_message: str,
    temperature: float = 0.2,
    use_fallback: bool = True,
):
    """Create Ollama-backed assistant with quiet error handling."""
    base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3:latest")
    
    connect_t = float(os.getenv("LLM_CONNECT_TIMEOUT", "10"))
    read_t = float(os.getenv("LLM_READ_TIMEOUT", "600"))
    num_predict = int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))
    num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))
    stream_enabled = os.getenv("LLM_STREAM", "1") == "1"
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))
    
    session = requests.Session()
    
    _log(f"[llm_bridge] model={model} url={base_url} num_predict={num_predict} ctx={num_ctx}")
    
    class Assistant:
        def __init__(self, name: str, system_message: str, temperature: float):
            self.name = name
            self.system_message = system_message
            self.temperature = float(temperature)

        def _extract_context(self, messages: List[Dict[str, str]]) -> Dict[str, str]:
            """Extract context from messages for fallback generation."""
            context = {"tool": "", "rule_id": "", "severity": "", "message": "", "file": "", "line": ""}
            for msg in messages:
                content = msg.get("content", "")
                content_lower = content.lower()
                
                # Extract tool
                for tool in ["semgrep", "trivy", "tfsec", "gitleaks", "conftest", "zap"]:
                    if tool in content_lower:
                        context["tool"] = tool
                        break
                
                # Extract severity
                for sev in ["critical", "high", "medium", "low"]:
                    if sev in content_lower:
                        context["severity"] = sev
                        break
                
                # Extract file path
                import re
                file_match = re.search(r'file[:\s]+([^\s\n]+)', content, re.I)
                if file_match:
                    context["file"] = file_match.group(1)
                
                line_match = re.search(r'line[:\s]+(\d+)', content, re.I)
                if line_match:
                    context["line"] = line_match.group(1)
                
                rule_match = re.search(r'rule[_\s]*id[:\s]+([^\s\n]+)', content, re.I)
                if rule_match:
                    context["rule_id"] = rule_match.group(1)
                
                context["message"] = content[:500]
            
            return context

        def chat_completion_fn(self, messages: List[Dict[str, str]]) -> str:
            """Call Ollama with quiet error handling."""
            chat_messages = [
                {"role": msg.get("role", "user"), "content": msg.get("content", "")}
                for msg in messages if msg.get("content")
            ]
            
            payload = {
                "model": model,
                "messages": chat_messages,
                "stream": stream_enabled,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": num_predict,
                    "num_ctx": num_ctx,
                }
            }
            
            chat_url = f"{base_url}/api/chat"
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    _log(f"[llm_bridge] Attempt {attempt+1}/{max_retries} for {self.name}")
                    
                    if stream_enabled:
                        acc = []
                        with session.post(chat_url, json=payload, stream=True, timeout=(connect_t, read_t)) as r:
                            r.raise_for_status()
                            for line in r.iter_lines():
                                if line:
                                    obj = json.loads(line.decode("utf-8"))
                                    if obj.get("message", {}).get("content"):
                                        acc.append(obj["message"]["content"])
                                    if obj.get("done"):
                                        break
                        return "".join(acc).strip()
                    else:
                        r = session.post(chat_url, json=payload, timeout=(connect_t, read_t))
                        r.raise_for_status()
                        return r.json().get("message", {}).get("content", "").strip()
                
                except requests.exceptions.HTTPError as e:
                    status = getattr(e.response, 'status_code', 'unknown')
                    last_error = f"HTTP {status}"
                    _log(f"[llm_bridge] HTTP error {status} on attempt {attempt+1}")
                    if attempt < max_retries - 1:
                        time.sleep(2 * (attempt + 1))
                
                except Exception as e:
                    last_error = str(e)
                    _log(f"[llm_bridge] Error on attempt {attempt+1}: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(2 * (attempt + 1))
            
            # Use fallback
            if use_fallback:
                ctx = self._extract_context(messages)
                fallback = get_fallback_suggestion(
                    tool=ctx["tool"],
                    rule_id=ctx["rule_id"],
                    severity=ctx["severity"],
                    message=ctx["message"],
                    file_path=ctx["file"],
                    line=ctx["line"],
                )
                _log(f"[llm_bridge] Using fallback for {self.name}")
                return f"[Fallback]\n\n{fallback}"
            
            raise RuntimeError(f"Ollama error: {last_error}")

    return Assistant(name, system_message, temperature)


# =============================================================================
# SIMPLE CHAT
# =============================================================================

def ollama_chat(
    system: str,
    user: str,
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    num_predict: Optional[int] = None,
    num_ctx: Optional[int] = None,
    use_fallback: bool = True,
) -> str:
    """Simple Ollama chat wrapper."""
    base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = model or os.getenv("OLLAMA_MODEL", "llama3:latest")
    num_ctx = num_ctx or int(os.getenv("OLLAMA_NUM_CTX", "8192"))
    num_predict = num_predict or int(os.getenv("OLLAMA_NUM_PREDICT", "2048"))
    
    payload = {
        "model": model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "options": {
            "temperature": float(temperature),
            "num_predict": int(num_predict),
            "num_ctx": int(num_ctx),
        },
    }

    try:
        r = requests.post(f"{base_url}/api/chat", json=payload, timeout=(10, 600))
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "").strip()
    except Exception as e:
        _log(f"[llm_bridge] Error: {e}")
        if use_fallback:
            return get_fallback_suggestion(tool="", severity="medium", message=user[:200])
        raise


if __name__ == "__main__":
    import sys
    os.environ["LLM_VERBOSE"] = "1"
    
    print("Ollama Diagnostics")
    print("-" * 40)
    
    health = check_ollama_health()
    print(f"Server: {'✓' if health['server_reachable'] else '✗'}")
    print(f"Model: {'✓' if health['model_available'] else '✗'} ({health['model_name']})")
    
    if health['error']:
        print(f"Error: {health['error']}")
    
    sys.exit(0 if health['healthy'] else 1)