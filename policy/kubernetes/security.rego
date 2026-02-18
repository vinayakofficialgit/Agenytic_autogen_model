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

# Allowed seccomp types (case-insensitive compare)
allowed_seccomp := {"runtimedefault", "localhost"}

########################################
# Helpers (Rego v1; no inline `or`)
########################################

# Iterate all top-level Kubernetes objects from:
#  - single doc
#  - multi-doc array
#  - kind: List
k8s_object(obj) if {
  obj := input
  obj.kind
}
k8s_object(obj) if {
  some i
  obj := input[i]
  obj.kind
}
k8s_object(obj) if {
  input.kind == "List"
  obj := input.items[_]
}

# Extract PodSpec from common workload kinds
podspec(obj, ps) if {
  lower(obj.kind) == "pod"
  ps := obj.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "deployment"
  ps := obj.spec.template.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "statefulset"
  ps := obj.spec.template.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "daemonset"
  ps := obj.spec.template.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "replicaset"
  ps := obj.spec.template.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "job"
  ps := obj.spec.template.spec
}
podspec(obj, ps) if {
  lower(obj.kind) == "cronjob"
  ps := obj.spec.jobTemplate.spec.template.spec
}

# Container iterators
workload_container(ps, c) if {
  ps.containers
  c := ps.containers[_]
}
init_container(ps, c) if {
  ps.initContainers
  c := ps.initContainers[_]
}

# ENV names (lowercased)
env_name(c, name) if {
  c.env
  e := c.env[_]
  name := lower(e.name)
}

# Secret-like name (avoid inline `or`)
secret_like(name, k) if { startswith(name, k) }
secret_like(name, k) if { endswith(name, k) }

# ENV name parts to catch tokens like FOO_API_KEY
env_name_part(name, p) if {
  parts := regex.split("[_\\.-]", name)
  p := lower(parts[_])
  p != ""
}

# Commands as lowercase strings (guard each field)
cmd_text(c, t) if {
  c.command
  t := lower(concat(" ", c.command))
}
cmd_text(c, t) if {
  c.args
  t := lower(concat(" ", c.args))
}
cmd_text(c, t) if {
  c.lifecycle
  c.lifecycle.postStart
  c.lifecycle.postStart.exec
  c.lifecycle.postStart.exec.command
  t := lower(concat(" ", c.lifecycle.postStart.exec.command))
}
cmd_text(c, t) if {
  c.lifecycle
  c.lifecycle.preStop
  c.lifecycle.preStop.exec
  c.lifecycle.preStop.exec.command
  t := lower(concat(" ", c.lifecycle.preStop.exec.command))
}

# Image tag checks
image_is_latest(img) if { endswith(lower(img), ":latest") }
image_missing_tag(img) if {
  not contains(img, ":")
  not contains(img, "@sha256:")
}
image_latest_or_missing(img) if { image_is_latest(img) }
image_latest_or_missing(img) if { image_missing_tag(img) }

# Registry allow-list
image_from_allowed_registry(img) if {
  some p
  p := allowed_registries[_]
  startswith(lower(img), lower(p))
}

# Capability helpers (predicates only)
added_cap(c, cap) if {
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.add
  a := c.securityContext.capabilities.add[_]
  cap := upper(a)
}
drops_all_caps(c) if {
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.drop
  lower(c.securityContext.capabilities.drop[_]) == "all"
}

# runAsNonRoot OK at container OR pod level
run_as_non_root_ok(ps, c) if { c.securityContext.runAsNonRoot == true }
run_as_non_root_ok(ps, c) if {
  ps.securityContext
  ps.securityContext.runAsNonRoot == true
}

# is root user (UID 0) at container OR pod level
is_root_user(ps, c) if { c.securityContext.runAsUser == 0 }
is_root_user(ps, c) if {
  ps.securityContext
  ps.securityContext.runAsUser == 0
}

# seccomp OK (RuntimeDefault or Localhost) at container OR pod level
seccomp_ok(ps, c) if {
  c.securityContext
  c.securityContext.seccompProfile
  t := lower(c.securityContext.seccompProfile.type)
  allowed_seccomp[t]
}
seccomp_ok(ps, c) if {
  ps.securityContext
  ps.securityContext.seccompProfile
  t := lower(ps.securityContext.seccompProfile.type)
  allowed_seccomp[t]
}

# allowPrivilegeEscalation must be explicitly false
allow_priv_escal_false(c) if {
  c.securityContext
  c.securityContext.allowPrivilegeEscalation == false
}

# readOnlyRootFilesystem must be explicitly true
read_only_fs_true(c) if {
  c.securityContext
  c.securityContext.readOnlyRootFilesystem == true
}

########################################
# 1) Potential secrets in ENV (names)
########################################

deny contains msg if {
  some obj, ps, c, name, k
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  env_name(c, name)
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (starts with %s): %s", [k, name])
}

deny contains msg if {
  some obj, ps, c, name, k
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  env_name(c, name)
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (ends with %s): %s", [k, name])
}

deny contains msg if {
  some obj, ps, c, name, p
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  env_name(c, name)
  env_name_part(name, p)
  suspicious_env_keys[p]
  msg := sprintf("Potential secret-like token in ENV name: %s", [p])
}

# Inline values for suspicious env names (suggest secretKeyRef)
warn contains msg if {
  some obj, ps, c, e, name, k
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  secret_like(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

warn contains msg if {
  some obj, ps, c, e, name, k
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  secret_like(name, k)
  msg := sprintf("INIT ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

########################################
# 2) Disallow :latest (or missing tag) in images
########################################

warn contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  image_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for container %q image: %s", [c.name, c.image])
}

warn contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  image_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for initContainer %q image: %s", [c.name, c.image])
}

########################################
# 3) Disallow package upgrade commands in command/args
########################################

deny contains msg if {
  some obj, ps, c, t
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  cmd_text(c, t)
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [u])
}

deny contains msg if {
  some obj, ps, c, t
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  cmd_text(c, t)
  u := pkg_update_commands[_]
  contains(t, lower(u))
  msg := sprintf("Do not run package upgrade commands in initContainers: %s", [u])
}

########################################
# 4) Disallow hostPath volumes (node FS escape risk)
########################################

deny contains msg if {
  some obj, ps, v
  k8s_object(obj)
  podspec(obj, ps)
  ps.volumes
  v := ps.volumes[_]
  v.hostPath
  msg := sprintf("hostPath volume is not allowed (name=%q, path=%q)", [v.name, v.hostPath.path])
}

########################################
# 5) Disallow sudo usage
########################################

deny contains msg if {
  some obj, ps, c, t
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  cmd_text(c, t)
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

deny contains msg if {
  some obj, ps, c, t
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  cmd_text(c, t)
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in initContainers: %s", [t])
}

########################################
# 6) Require CPU/Memory requests and limits (containers & initContainers)
########################################

# Containers
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# InitContainers
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  not c.resources
  msg := sprintf("initContainer %q missing resources", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  not c.resources.requests
  msg := sprintf("initContainer %q missing resources.requests", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  not c.resources.limits
  msg := sprintf("initContainer %q missing resources.limits", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  c.resources.requests
  not c.resources.requests.cpu
  msg := sprintf("initContainer %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  c.resources.requests
  not c.resources.requests.memory
  msg := sprintf("initContainer %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  c.resources.limits
  not c.resources.limits.cpu
  msg := sprintf("initContainer %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  c.resources
  c.resources.limits
  not c.resources.limits.memory
  msg := sprintf("initContainer %q missing resources.limits.memory", [c.name])
}

########################################
# 7) Require liveness & readiness probes (containers)
########################################

deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}

deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

########################################
# 8) SecurityContext hardening
########################################

# Not privileged
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  c.securityContext
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}

# allowPrivilegeEscalation: false (explicit)
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not allow_priv_escal_false(c)
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# readOnlyRootFilesystem: true (explicit)
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not read_only_fs_true(c)
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

# runAsNonRoot true at container or pod level
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not run_as_non_root_ok(ps, c)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

# must not run as UID 0 (container or pod level)
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  is_root_user(ps, c)
  msg := sprintf("container %q must not run as root user (runAsUser: 0)", [c.name])
}

# capabilities: disallow additions outside allow-list
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  ac := {cap | added_cap(c, cap); not allowed_add_caps[cap]}
  count(ac) > 0
  msg := sprintf("container %q adds disallowed Linux capabilities: %v", [c.name, ac])
}

# capabilities: recommend drop: ["ALL"]
warn contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not drops_all_caps(c)
  msg := sprintf("container %q should drop all capabilities (capabilities.drop: [\"ALL\"])", [c.name])
}

# seccomp: require RuntimeDefault or Localhost
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not seccomp_ok(ps, c)
  msg := sprintf("container %q must set a secure seccompProfile (RuntimeDefault or Localhost)", [c.name])
}

########################################
# 9) Disallow hostNetwork / hostPID / hostIPC
########################################

deny contains msg if {
  some obj, ps
  k8s_object(obj)
  podspec(obj, ps)
  ps.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  some obj, ps
  k8s_object(obj)
  podspec(obj, ps)
  ps.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  some obj, ps
  k8s_object(obj)
  podspec(obj, ps)
  ps.hostIPC == true
  msg := "hostIPC must be disabled"
}

########################################
# 10) Allowed image registries (strict allow-list)
########################################

deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  workload_container(ps, c)
  not image_from_allowed_registry(c.image)
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}
deny contains msg if {
  some obj, ps, c
  k8s_object(obj)
  podspec(obj, ps)
  init_container(ps, c)
  not image_from_allowed_registry(c.image)
  msg := sprintf("initContainer %q image %q is not from an allowed registry", [c.name, c.image])
}