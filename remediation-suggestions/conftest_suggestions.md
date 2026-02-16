# 📋 Conftest — Policy Compliance Analysis

Generated: 2026-02-16 16:13 UTC

Mode: **Remediation**

---

## 🟢 Improvement Suggestions

Pipeline passed. These are proactive policy hardening recommendations.


Certainly! Here are some policy-as-code best practices along with example Rego policy snippets:

### 1. OPA/Rego Policy Patterns for Kubernetes Security

#### Example: Deny Unauthorized API Calls
```rego
package kubernetes.api

deny[msg] {
    input.request.method == "POST" && !input.request.headers["Authorization"]
}
```

#### Example: Require TLS for API Requests
```rego
package kubernetes.api

require tls

deny[msg] {
    input.request.scheme != "https"
}
```

### 2. Terraform Compliance Policies (Tagging, Encryption, Networking)

#### Example: Tag Resources with Specific Tags
```rego
package terraform.tags

deny[msg] {
    !input.resource.tags["Environment"] == "Production"
}
```

#### Example: Encrypt Sensitive Data in State Files
```rego
package terraform.encryption

require encryption

deny[msg] {
    input.resource.type == "aws_ssm_parameter" && !input.resource.sensitive
}
```

#### Example: Ensure Network Policies Are Applied to All Resources
```rego
package terraform.networking

deny[msg] {
    !input.resource.network_policy
}
```

### 3. Custom Conftest Rules to Add to CI/CD

#### Example: Validate Kubernetes Deployment YAML Files
```rego
package kubernetes.deployment

require deployment

deny[msg] {
    input.spec.template.metadata.labels["app"] == "example-app"
}
```

#### Example: Ensure Secrets Are Encrypted in Terraform State Files
```rego
package terraform.secrets

require encryption

deny[msg] {
    input.resource.type == "aws_kms_key" && !input.resource.encryption_context["kms-key-id"]
}
```

### 4. Policy Testing and Validation Strategies

#### Example: Use Conftest with CI/CD Pipeline
```yaml
# .github/workflows/conftest.yml
name: Conftest Tests

on:
  push:
    branches:
      - main

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Install Conftest
      run: |
        curl -L https://github.com/open-policy-agent/conftest/releases/download/v0.39.1/conftest-linux-amd64 > conftest
        chmod +x conftest

    - name: Run Conftest Tests
      run: |
        ./conftest scan . --fail-on-error
```

#### Example: Use Rego for Policy Testing
```rego
package policy.test

deny[msg] {
    input.request.method == "POST" && !input.request.headers["Authorization"]
}
```

### 5. Governance and Audit Trail Recommendations

#### Example: Implement Role-Based Access Control (RBAC)
```rego
package rbac

require rbac

deny[msg] {
    input.request.action != "read"
}
```

#### Example: Enable Logging for Security Events
```rego
package logging

require logging

deny[msg] {
    !input.request.log_level == "info"
}
```

These examples should help you implement effective policy-as-code practices in your Kubernetes and Terraform environments.

