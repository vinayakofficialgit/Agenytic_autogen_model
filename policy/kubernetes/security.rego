package k8s.security

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

# Allowed image registries/prefixes
allowed_registries := {
  "registry.k8s.io/",
  "ghcr.io/your-org/",
  "your-private-registry.example.com/",
}

# Allowed capabilities (ideally keep empty)
allowed_add_caps := {
  "NET_BIND_SERVICE",
}

########################################
# Object selectors (Deployment / Pod)
########################################

is_deploy if { input.kind; lower(input.kind) == "deployment" }
is_pod    if { input.kind; lower(input.kind) == "pod" }

########################################
# Helper (single-body, no var redeclare)
########################################

# True if image starts with any allowed registry prefix (case-insensitive)
allowed_registry_match(img) if {
  p := allowed_registries[_]
  startswith(lower(img), lower(p))
}

########################################
# 1 ENV secret-like names + inline values
########################################

# Deployment
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name (starts with %s): %s", [k, e.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name (ends with %s): %s", [k, e.name])
}
warn contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
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
  c := input.spec.template.spec.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

# Pod
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name (starts with %s): %s", [k, e.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name (ends with %s): %s", [k, e.name])
}
warn contains msg if {
  is_pod
  c := input.spec.containers[_]
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
  c := input.spec.containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

########################################
# 2 :latest or missing tag (warn)
########################################

# Deployment
warn contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  endswith(lower(c.image), ":latest")
  msg := sprintf("Avoid :latest tag for container %q image: %s", [c.name, c.image])
}
warn contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  not contains(c.image, ":")
  not contains(c.image, "@sha256:")
  msg := sprintf("Image tag missing (defaults to latest) for container %q: %s", [c.name, c.image])
}

# Pod
warn contains msg if {
  is_pod
  c := input.spec.containers[_]
  endswith(lower(c.image), ":latest")
  msg := sprintf("Avoid :latest tag for container %q image: %s", [c.name, c.image])
}
warn contains msg if {
  is_pod
  c := input.spec.containers[_]
  not contains(c.image, ":")
  not contains(c.image, "@sha256:")
  msg := sprintf("Image tag missing (defaults to latest) for container %q: %s", [c.name, c.image])
}

########################################
# 3 Disallow package upgrades & sudo
########################################

# Deployment
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

# Pod
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.command
  t := lower(concat(" ", c.command))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.args
  t := lower(concat(" ", c.args))
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

########################################
# 4 Disallow hostPath volumes
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
# 5 Require CPU/Memory requests & limits
########################################

# Deployment
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# Pod
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

########################################
# 6 Liveness & Readiness probes
########################################

# Deployment
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

# Pod
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

########################################
# 7 SecurityContext hardening — runAsNonRoot
########################################

# Deployment: require runAsNonRoot: true at container OR pod-template level
deny contains msg if {
  is_deploy
  ps := input.spec.template.spec
  c := ps.containers[_]

  not container_run_as_non_root_true(c)
  not pod_run_as_non_root_true(ps)

  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

# Pod: require runAsNonRoot: true at container OR pod level
deny contains msg if {
  is_pod
  ps := input.spec
  c := ps.containers[_]

  not container_run_as_non_root_true(c)
  not pod_run_as_non_root_true(ps)

  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

########################################
# 8 Disallow hostNetwork / hostPID / hostIPC
########################################

deny contains msg if {
  is_deploy
  input.spec.template.spec.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  is_pod
  input.spec.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  is_deploy
  input.spec.template.spec.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  is_pod
  input.spec.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  is_deploy
  input.spec.template.spec.hostIPC == true
  msg := "hostIPC must be disabled"
}
deny contains msg if {
  is_pod
  input.spec.hostIPC == true
  msg := "hostIPC must be disabled"
}

########################################
# 9 Allowed image registries (strict allow-list)
########################################

deny contains msg if {
  is_deploy
  c := input.spec.template.spec.containers[_]
  not allowed_registry_match(c.image)
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}
deny contains msg if {
  is_pod
  c := input.spec.containers[_]
  not allowed_registry_match(c.image)
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}