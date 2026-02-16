# 📋 Conftest — Policy Compliance Analysis

Generated: 2026-02-16 15:52 UTC

Mode: **Remediation**

---

## 🟢 Improvement Suggestions

Pipeline passed. These are proactive policy hardening recommendations.


### 1. OPA/Rego Policy Patterns for Kubernetes Security

#### Example: Deny Pods with High CPU Usage
```rego
package kubernetes.security

deny[msg] {
    pod := input.pods[_]
    cpu_usage := pod.status.cpu.usage
    if cpu_usage > 80 {
        msg = "High CPU usage detected in pod: " + pod.metadata.name
    }
}
```

#### Example: Deny Pods with High Memory Usage
```rego
package kubernetes.security

deny[msg] {
    pod := input.pods[_]
    memory_usage := pod.status.memory.usage
    if memory_usage > 80 {
        msg = "High memory usage detected in pod: " + pod.metadata.name
    }
}
```

#### Example: Deny Pods with Unhealthy Containers
```rego
package kubernetes.security

deny[msg] {
    pod := input.pods[_]
    container := pod.spec.containers[_]
    if container.status.state.running == false {
        msg = "Unhealthy container detected in pod: " + pod.metadata.name
    }
}
```

### 2. Terraform Compliance Policies (Tagging, Encryption, Networking)

#### Example: Tagging Resources with a Specific Label
```rego
package terraform.compliance

deny[msg] {
    resource := input.resources[_]
    if resource.type == "aws_instance" && !has_tag(resource.tags, "environment") {
        msg = "Missing 'environment' tag on AWS instance: " + resource.id
    }
}
```

#### Example: Encrypting Sensitive Data in Terraform State Files
```rego
package terraform.compliance

deny[msg] {
    state := input.state[_]
    if has_sensitive_data(state, "password") {
        msg = "Sensitive data found in Terraform state file"
    }
}
```

#### Example: Network Policies for Security
```rego
package kubernetes.security

deny[msg] {
    pod := input.pods[_]
    network_policy := pod.spec.network_policies[_]
    if network_policy.policy_type == "Ingress" && !has_allowed_ip(network_policy, "192.168.1.0/24") {
        msg = "Denied ingress from IP address: " + pod.metadata.name
    }
}
```

### 3. Custom Conftest Rules to Add to CI/CD

#### Example: Validate Kubernetes YAML Files with Rego
```rego
package kubernetes.validation

deny[msg] {
    yaml := input.yaml[_]
    if !validate_yaml(yaml) {
        msg = "Invalid Kubernetes YAML file: " + yaml
    }
}

validate_yaml[yaml] {
    result := validate_json(yaml)
    result == "success"
}
```

#### Example: Validate Terraform Plan with Rego
```rego
package terraform.validation

deny[msg] {
    plan := input.plan[_]
    if !validate_plan(plan) {
        msg = "Invalid Terraform plan: " + plan
    }
}

validate_plan[plan] {
    result := validate_json(plan)
    result == "success"
}
```

### 4. Policy Testing and Validation Strategies

#### Example: Run Conftest on CI/CD Pipeline
```yaml
# .github/workflows/ci.yml
name: CI

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
      uses: conftest/actions/setup@v1

    - name: Run Conftest
      run: |
        conftest scan --format json . > results.json
        cat results.json | jq '.failures'
```

#### Example: Use Rego for Policy Testing in CI/CD
```yaml
# .github/workflows/policy.yml
name: Policy

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

    - name: Set up Rego
      uses: conftest/actions/setup@v1

    - name: Run Rego policy tests
      run: |
        conftest scan --format json . > results.json
        cat results.json | jq '.failures'
```

### 5. Governance and Audit Trail Recommendations

#### Example: Implement Role-Based Access Control (RBAC) in Kubernetes
```rego
package kubernetes.governance

deny[msg] {
    role := input.roles[_]
    if !has_permission(role, "edit") && !has_permission(role, "delete") {
        msg = "Role lacks necessary permissions: " + role.metadata.name
    }
}
```

#### Example: Enable Audit Logging in Kubernetes
```rego
package kubernetes.governance

deny[msg] {
    cluster := input.clusters[_]
    if !has_audit_logging(cluster) {
        msg = "Audit logging is not enabled for cluster: " + cluster.metadata.name
    }
}
```

These examples provide a starting point for implementing policy-as-code best practices in your organization. You can customize and expand these patterns based on your specific requirements and security policies.

