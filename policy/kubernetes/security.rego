package kubernetes.security

########################################
# Config (tune for your org)
########################################

suspicious_env_keys := {
  "passwd",
  "password",
  "secret",
  "key",
  "access",
  "api_key",
  "apikey",
  "token",
}

pkg_update_commands := {
  "apk upgrade",
  "apt-get upgrade",
  "dist-upgrade",
}

# Allowed image registries/prefixes (edit for your org)
allowed_registries := {
  "registry.k8s.io/",
  "ghcr.io/your-org/",
  "your-private-registry.example.com/",
}

# Capabilities allowed to be added (ideally keep this empty)
allowed_add_caps := {
  "NET_BIND_SERVICE",
}
########################################
# 0) Common object selection (Deployment/Pod only)
########################################
# For Deployment
is_deploy if { input.kind; lower(input.kind) == "deployment" }
# For Pod
is_pod if { input.kind; lower(input.kind) == "pod" }

########################################
# 1) ENV secret-like names + inline values
########################################

# Deployment: containers
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name (starts with %s): %s", [k, e.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name (ends with %s): %s", [k, e.name])
}

# Pod: containers
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name (starts with %s): %s", [k, e.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name (ends with %s): %s", [k, e.name])
}

# Deployment: inline values for secret-like names (warn)
warn contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}
warn contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

# Pod: inline values for secret-like names (warn)
warn contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}
warn contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

########################################
# 2) :latest or missing image tag (warn)
########################################

# Deployment containers
warn contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  img := lower(c.image)
  endswith(img, ":latest")
  msg := sprintf("Avoid :latest tag for container %q image: %s", [c.name, c.image])
}
warn contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  img := c.image
  not contains(img, ":")
  not contains(img, "@sha256:")
  msg := sprintf("Image tag missing (defaults to latest) for container %q: %s", [c.name, img])
}

# Pod containers
warn contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  img := lower(c.image)
  endswith(img, ":latest")
  msg := sprintf("Avoid :latest tag for container %q image: %s", [c.name, c.image])
}
warn contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  img := c.image
  not contains(img, ":")
  not contains(img, "@sha256:")
  msg := sprintf("Image tag missing (defaults to latest) for container %q: %s", [c.name, img])
}

########################################
# 3) Disallow package upgrades & sudo in commands/args/lifecycle
########################################

# Helper body duplicated across Deployment/Pod and command/args/lifecycle to avoid undefined refs.

# Deployment
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.lifecycle
  c.lifecycle.postStart.exec.command
  t := lower(concat(" ", c.lifecycle.postStart.exec.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.lifecycle
  c.lifecycle.preStop.exec.command
  t := lower(concat(" ", c.lifecycle.preStop.exec.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

# Pod
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

########################################
# 4) Disallow hostPath volumes
########################################

deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.volumes
  v := ps.volumes[_]
  v.hostPath
  msg := sprintf("hostPath volume is not allowed (name=%q, path=%q)", [v.name, v.hostPath.path])
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.volumes
  v := ps.volumes[_]
  v.hostPath
  msg := sprintf("hostPath volume is not allowed (name=%q, path=%q)", [v.name, v.hostPath.path])
}

########################################
# 5) Require CPU/Memory requests & limits
########################################

# Deployment
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# Pod
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

########################################
# 6) Liveness & Readiness probes
########################################

deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

########################################
# 7) SecurityContext hardening
########################################

# Not privileged
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}

# allowPrivilegeEscalation: false
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  not c.securityContext
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  not c.securityContext
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.allowPrivilegeEscalation != false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# readOnlyRootFilesystem: true
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  not c.securityContext
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  not c.securityContext
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

# runAsNonRoot true (either pod or container)
# Case A: pod has no securityContext
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  not ps.securityContext
  c := ps.containers[_]
  (not c.securityContext) or (c.securityContext.runAsNonRoot != true)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  not ps.securityContext
  c := ps.containers[_]
  (not c.securityContext) or (c.securityContext.runAsNonRoot != true)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}
# Case B: pod has securityContext but not true
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.securityContext
  ps.securityContext.runAsNonRoot != true
  c := ps.containers[_]
  (not c.securityContext) or (c.securityContext.runAsNonRoot != true)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.securityContext
  ps.securityContext.runAsNonRoot != true
  c := ps.containers[_]
  (not c.securityContext) or (c.securityContext.runAsNonRoot != true)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

# Must not run as UID 0 (either pod or container)
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.securityContext
  ps.securityContext.runAsUser == 0
  c := ps.containers[_]
  msg := sprintf("container %q must not run as root user (pod runAsUser: 0)", [c.name])
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.runAsUser == 0
  msg := sprintf("container %q must not run as root user (runAsUser: 0)", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.securityContext
  ps.securityContext.runAsUser == 0
  c := ps.containers[_]
  msg := sprintf("container %q must not run as root user (pod runAsUser: 0)", [c.name])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.runAsUser == 0
  msg := sprintf("container %q must not run as root user (runAsUser: 0)", [c.name])
}

# Capabilities: disallow additions outside allow-list
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.add
  a := c.securityContext.capabilities.add[_]
  cap := upper(a)
  not allowed_add_caps[cap]
  msg := sprintf("container %q adds disallowed Linux capability: %s", [c.name, cap])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.add
  a := c.securityContext.capabilities.add[_]
  cap := upper(a)
  not allowed_add_caps[cap]
  msg := sprintf("container %q adds disallowed Linux capability: %s", [c.name, cap])
}

########################################
# 8) Disallow hostNetwork / hostPID / hostIPC
########################################

deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  ps.hostIPC == true
  msg := "hostIPC must be disabled"
}
deny contains msg if {
  is_pod
  ps := input.spec
  ps.hostIPC == true
  msg := "hostIPC must be disabled"
}

########################################
# 9) Allowed image registries (strict allow-list)
########################################

deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]
  img := lower(c.image)
  not some p
  p := allowed_registries[_]
  startswith(img, lower(p))
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]
  img := lower(c.image)
  not some p
  p := allowed_registries[_]
  startswith(img, lower(p))
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}