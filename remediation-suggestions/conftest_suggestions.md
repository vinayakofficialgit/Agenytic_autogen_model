# 📋 Conftest — Policy Compliance Analysis

Generated: 2026-02-18 06:55 UTC

Mode: **Remediation**

---

## 🟢 Improvement Suggestions

Pipeline passed. These are proactive policy hardening recommendations.


### 1. OPA/Rego Policy Patterns for Kubernetes Security

#### Example: Deny Access to Secrets Without Annotations
```rego
package kubernetes.secrets

deny[msg] {
  input.resource.kind == "Secret"
  not input.resource.metadata.annotations["kubernetes.io/service-account-token"]
}
```

#### Example: Require Encryption on Sensitive Data in Secrets
```rego
package kubernetes.secrets

require {
  data.encryption.key != ""
}

allow[msg] {
  input.resource.kind == "Secret"
  data.encryption.key == input.resource.data["encryption-key"]
}
```

### 2. Terraform Compliance Policies (Tagging, Encryption, Networking)

#### Example: Tag Resources with Specific Tags
```rego
package terraform.tags

require {
  data.tag.value != ""
}

allow[msg] {
  input.resource.type == "aws_instance"
  data.tag.key == "Environment"
}
```

#### Example: Encrypt Sensitive Data in Terraform State Files
```rego
package terraform.encryption

require {
  data.encrypted.state_file != ""
}

allow[msg] {
  input.resource.type == "terraform_state"
  data.encrypted.state_file == input.resource.data["encrypted-state-file"]
}
```

#### Example: Restrict Network Access to Specific Subnets
```rego
package terraform.network

require {
  data.subnet.value != ""
}

allow[msg] {
  input.resource.type == "aws_instance"
  data.subnet.value == input.resource.data["subnet"]
}
```

### 3. Custom Conftest Rules to Add to CI/CD

#### Example: Validate Kubernetes Deployment YAML
```rego
package kubernetes.deployment

require {
  data.spec.template.spec.containers != ""
}

allow[msg] {
  input.resource.type == "kubernetes_deployment"
  data.spec.template.spec.containers[0].name == "my-container"
}
```

#### Example: Check for Missing Required Environment Variables in Kubernetes Deployment
```rego
package kubernetes.deployment

require {
  data.env.value != ""
}

allow[msg] {
  input.resource.type == "kubernetes_deployment"
  data.spec.template.spec.containers[0].env[0].name == "MY_ENV_VAR"
}
```

### 4. Policy Testing and Validation Strategies

#### Example: Use Conftest with CI/CD Pipeline
```yaml
# .github/workflows/conftest.yml
name: Conftest

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

    - name: Set up Conftest
      uses: conftest/conftest-action@v1.0.0

    - name: Run Conftest
      run: |
        conftest scan --config .conftest.yml .
```

#### Example: Use Rego for Policy Testing and Validation
```rego
package kubernetes.secrets

deny[msg] {
  input.resource.kind == "Secret"
  not input.resource.metadata.annotations["kubernetes.io/service-account-token"]
}
```

### 5. Governance and Audit Trail Recommendations

#### Example: Implement Role-Based Access Control (RBAC) in Kubernetes
```yaml
# kube-config.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: my-cluster-role-binding
subjects:
- kind: ServiceAccount
  name: my-service-account
roleRef:
  kind: ClusterRole
  name: cluster-admin
```

#### Example: Enable Logging in Kubernetes
```yaml
# kube-config.yaml
apiVersion: v1
kind: PodSecurityPolicy
metadata:
  name: my-pod-security-policy
spec:
  requiredDropCapabilities:
    - CAP_SYS_ADMIN
  allowPrivilegedContainers: true
```

By implementing these policy-as-code best practices, you can enhance the security and compliance of your Kubernetes environment.

