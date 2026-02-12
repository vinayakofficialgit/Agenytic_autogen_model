# Recommended Security Changes

Based on the findings from Semgrep and Trivy security scans, here are the specific changes that should be made to the codebase:

---

## 1. 🔴 CRITICAL: Remove Hardcoded Password from app/main.py (Line 12)

### Current Issue
- **Severity:** HIGH
- **Finding ID:** TEST001 (Semgrep)
- **Risk:** Hardcoded passwords are easily discoverable and allow unauthorized access

### Recommended Change
**Action:** Remove any hardcoded passwords and implement environment variable-based configuration.

**Steps:**
1. Search for hardcoded credentials in `app/main.py` (line 12)
2. Replace with environment variable: `password = os.getenv('APP_PASSWORD')`
3. Add `import os` at the top if not already present
4. Create a `.env.example` file showing required environment variables
5. Add `.env` to `.gitignore` to prevent accidental commits

**Example Code:**
```python
# BEFORE (INSECURE)
password = "hardcoded_password_123"

# AFTER (SECURE)
import os
password = os.getenv('APP_PASSWORD', '')
if not password:
    raise ValueError("APP_PASSWORD environment variable is not set")
```

**Follow-up:** Implement a secrets management system (HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault)

---

## 2. 🔴 HIGH: Fix insecure_eval.py - Code Injection Vulnerability

### Current Issue
- **Location:** `app/insecure_eval.py`
- **Risk:** The `eval()` function accepts arbitrary code execution, leading to critical security vulnerabilities
- **Impact:** Remote Code Execution (RCE) vulnerability

### Recommended Change
**Action:** Remove or replace the unsafe `eval()` function.

**Current Code:**
```python
def run(code):
    return eval(code)  # DANGEROUS!
```

**Secure Alternative Options:**

**Option 1: Use AST-based safe evaluation (recommended)**
```python
import ast
import operator

def safe_eval(code_string):
    """Safely evaluate mathematical expressions without executing arbitrary code"""
    node = ast.parse(code_string, mode='eval')
    
    # Whitelist of safe operations
    allowed_ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
    }
    
    def _eval(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.BinOp):
            op = allowed_ops.get(type(node.op))
            if op is None:
                raise ValueError(f"Operation not allowed: {type(node.op)}")
            return op(_eval(node.left), _eval(node.right))
        else:
            raise ValueError(f"Expression type not allowed: {type(node)}")
    
    return _eval(node.body)
```

**Option 2: Use `numexpr` library (for math expressions)**
```python
import numexpr as ne

def safe_eval(code):
    return ne.evaluate(code)
```

**Option 3: Remove functionality entirely**
If the feature isn't critical, remove the function entirely and use direct Python code instead.

---

## 3. 🔴 HIGH: Fix Dockerfile CVE-2025-0001 (OpenSSL)

### Current Issue
- **Severity:** HIGH
- **Vulnerability:** Outdated OpenSSL version
- **Finding ID:** CVE-2025-0001 (Trivy-FS)

### Recommended Change
**Action:** Update the base image and ensure latest security patches.

**Current Dockerfile:**
```dockerfile
FROM python:3.12-slim
```

**Recommended Changes:**
```dockerfile
# Use latest stable version and ensure security patches
FROM python:3.12.1-slim-bookworm

# Update system packages to latest versions
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        openssl=3.0.13-1~deb12u1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Rest of Dockerfile remains the same
```

**Additional Best Practices:**
- Regularly rebuild Docker images (at least monthly)
- Implement automated dependency updates
- Use tools like Dependabot or Renovate for automated updates
- Add a security scanning step in CI/CD pipeline

---

## 4. 🟡 MEDIUM: Ensure Non-Root User in Dockerfile

### Current Status
✅ **ALREADY FIXED** - The current Dockerfile correctly implements non-root user:
```dockerfile
RUN (adduser --disabled-password --gecos '' appuser) || (adduser -D appuser) || (useradd -m appuser || true)
USER appuser
```

**Verification:** No additional changes needed for this issue.

---

## 5. ✅ Kubernetes Deployment - Already Secured

### Current Status
✅ **PARTIALLY GOOD** - The deployment YAML includes:
```yaml
securityContext:
  runAsNonRoot: true
```

### Recommended Enhancements
Add more security hardening to `k8s/deployment.yaml`:
```yaml
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1001
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        cpu: 250m
        memory: 256Mi
      requests:
        cpu: 100m
        memory: 128Mi
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
  podSecurityPolicy: restricted
```

---

## 6. ✅ Terraform Security Group - Already Improved

### Current Status
✅ **GOOD** - The CIDR block is already restricted:
```hcl
cidr_blocks = ["10.0.0.0/24"]
```

### Recommended Enhancements
Add egress rules for complete network control:
```hcl
resource "aws_security_group" "open_demo" {
  name        = "open-demo"
  description = "Restricted ingress rules"
  
  # Ingress: Only allow from specific CIDR
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
  
  # Egress: Explicitly define allowed outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "restricted-demo"
    Environment = "production"
  }
}
```

---

## Summary of Priority Changes

| Priority | File | Issue | Action |
|----------|------|-------|--------|
| 🔴 CRITICAL | `app/main.py` | Hardcoded password | Remove and use environment variables |
| 🔴 CRITICAL | `app/insecure_eval.py` | Code injection via `eval()` | Replace with safe evaluation method |
| 🔴 HIGH | `app/Dockerfile` | CVE-2025-0001 OpenSSL | Update base image and packages |
| 🟡 MEDIUM | `app/Dockerfile` | Non-root user | ✅ Already fixed |
| 🟢 LOW | `k8s/deployment.yaml` | Security hardening | Add security contexts |
| 🟢 LOW | `terraform/main.tf` | Network security | Add egress rules |

---

## Implementation Checklist

- [ ] Remove hardcoded password from `app/main.py`
- [ ] Implement environment variable configuration
- [ ] Fix `app/insecure_eval.py` - replace `eval()` with safe alternative
- [ ] Update `app/Dockerfile` - upgrade base image and OpenSSL
- [ ] Add security contexts to `k8s/deployment.yaml`
- [ ] Add egress rules to `terraform/main.tf`
- [ ] Update CI/CD pipeline with security scanning
- [ ] Implement automated dependency updates
- [ ] Run security scans again to verify fixes
- [ ] Add security tests to prevent regressions

