package k8s.security

default deny = []

# ============================================================
# 1. Enforce runAsNonRoot at Pod level
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Pod must set securityContext.runAsNonRoot=true"
}

# ============================================================
# 2. Prevent privileged containers
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  container.securityContext.privileged == true
  msg := sprintf("Container %q must not run privileged", [container.name])
}

# ============================================================
# 3. Disallow running as root user
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  container.securityContext.runAsUser == 0
  msg := sprintf("Container %q must not run as UID 0 (root)", [container.name])
}

# ============================================================
# 4. Require resource limits AND requests
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.resources.limits
  msg := sprintf("Container %q must define resource limits", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.resources.requests
  msg := sprintf("Container %q must define resource requests", [container.name])
}

# ============================================================
# 5. Require dropping ALL Linux capabilities
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.securityContext.capabilities.drop
  msg := sprintf("Container %q must drop Linux capabilities", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not "ALL" in container.securityContext.capabilities.drop
  msg := sprintf("Container %q should drop ALL capabilities", [container.name])
}

# ============================================================
# 6. Enforce readOnlyRootFilesystem
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container %q should enable readOnlyRootFilesystem", [container.name])
}

# ============================================================
# 7. Disallow hostNetwork / hostPID / hostIPC
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.hostNetwork == true
  msg := "hostNetwork must not be enabled"
}

deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.hostPID == true
  msg := "hostPID must not be enabled"
}

deny[msg] {
  input.kind == "Deployment"
  input.spec.template.spec.hostIPC == true
  msg := "hostIPC must not be enabled"
}

# ============================================================
# 8. Disallow hostPath volumes
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some v
  vol := input.spec.template.spec.volumes[v]
  vol.hostPath
  msg := sprintf("hostPath volume %q is not allowed", [vol.name])
}

# ============================================================
# 9. Disallow :latest image tag
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  endswith(lower(container.image), ":latest")
  msg := sprintf("Container %q must not use :latest tag", [container.name])
}

# ============================================================
# 10. Require liveness and readiness probes
# ============================================================
deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.livenessProbe
  msg := sprintf("Container %q must define livenessProbe", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  some i
  container := input.spec.template.spec.containers[i]
  not container.readinessProbe
  msg := sprintf("Container %q must define readinessProbe", [container.name])
}