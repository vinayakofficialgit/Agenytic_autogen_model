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

# Allowed seccomp types (normalized to lowercase)
allowed_seccomp := {"runtimedefault", "localhost"}

########################################
# Helpers (safe & OR-free)
########################################

# Support single-doc, multi-doc array, and kind: List
k8s_objs[obj] {
  obj := input
  obj.kind
}
k8s_objs[obj] {
  some i
  obj := input[i]
  obj.kind
}
k8s_objs[obj] {
  input.kind == "List"
  obj := input.items[_]
}

# Extract PodSpecs from common workload kinds
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "pod"
  ps := o.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "deployment"
  ps := o.spec.template.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "statefulset"
  ps := o.spec.template.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "daemonset"
  ps := o.spec.template.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "replicaset"
  ps := o.spec.template.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "job"
  ps := o.spec.template.spec
}
pod_specs[ps] {
  o := k8s_objs[_]
  lower(o.kind) == "cronjob"
  ps := o.spec.jobTemplate.spec.template.spec
}

# Containers and initContainers
all_containers[c] {
  ps := pod_specs[_]
  ps.containers
  c := ps.containers[_]
}
all_init_containers[c] {
  ps := pod_specs[_]
  ps.initContainers
  c := ps.initContainers[_]
}

# Pod-level securityContext
pod_sc[psc] {
  ps := pod_specs[_]
  psc := ps.securityContext
}

# ENV names (lowercased)
env_names[name] {
  c := all_containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
}
env_names[name] {
  c := all_init_containers[_]
  c.env
  e := c.env[_]
  name := lower(e.name)
}

# ENV name parts to catch tokens like FOO_API_KEY
env_name_parts[p] {
  name := env_names[_]
  parts := regex.split("[_\\.-]", name)
  p := lower(parts[_])
  p != ""
}

# Aggregate command/args/lifecycle exec commands (lowercased),
# using separate rules so missing fields don't break evaluation.
cmd_texts[t] {
  c := all_containers[_]
  c.command
  t := lower(concat(" ", c.command))
}
cmd_texts[t] {
  c := all_containers[_]
  c.args
  t := lower(concat(" ", c.args))
}
cmd_texts[t] {
  c := all_init_containers[_]
  c.command
  t := lower(concat(" ", c.command))
}
cmd_texts[t] {
  c := all_init_containers[_]
  c.args
  t := lower(concat(" ", c.args))
}
cmd_texts[t] {
  c := all_containers[_]
  c.lifecycle
  c.lifecycle.postStart.exec.command
  t := lower(concat(" ", c.lifecycle.postStart.exec.command))
}
cmd_texts[t] {
  c := all_containers[_]
  c.lifecycle
  c.lifecycle.preStop.exec.command
  t := lower(concat(" ", c.lifecycle.preStop.exec.command))
}
cmd_texts[t] {
  c := all_init_containers[_]
  c.lifecycle
  c.lifecycle.postStart.exec.command
  t := lower(concat(" ", c.lifecycle.postStart.exec.command))
}
cmd_texts[t] {
  c := all_init_containers[_]
  c.lifecycle
  c.lifecycle.preStop.exec.command
  t := lower(concat(" ", c.lifecycle.preStop.exec.command))
}

# Image tag checks
image_is_latest(img) {
  endswith(lower(img), ":latest")
}
image_missing_tag(img) {
  not contains(img, ":")
  not contains(img, "@sha256:")
}
image_latest_or_missing(img) {
  image_is_latest(img)
}
image_latest_or_missing(img) {
  image_missing_tag(img)
}

# Registry allow-list
image_from_allowed_registry(img) {
  some p
  p := allowed_registries[_]
  startswith(lower(img), lower(p))
}

# Capability helpers — use predicates (no partial-set-with-args)
added_cap(c, cap) {
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.add
  a := c.securityContext.capabilities.add[_]
  cap := upper(a)
}
drops_all_caps(c) {
  c.securityContext
  c.securityContext.capabilities
  c.securityContext.capabilities.drop
  lower(c.securityContext.capabilities.drop[_]) == "all"
}

# runAsNonRoot OK at container OR pod level
run_as_non_root_ok(c) {
  c.securityContext.runAsNonRoot == true
}
run_as_non_root_ok(c) {
  psc := pod_sc[_]
  psc.runAsNonRoot == true
}

# is root user (UID 0) at container OR pod level
is_root_user(c) {
  c.securityContext.runAsUser == 0
}
is_root_user(c) {
  psc := pod_sc[_]
  psc.runAsUser == 0
}

# seccomp OK (RuntimeDefault or Localhost) at container OR pod level
seccomp_ok(c) {
  c.securityContext
  c.securityContext.seccompProfile
  t := lower(c.securityContext.seccompProfile.type)
  allowed_seccomp[t]
}
seccomp_ok(c) {
  psc := pod_sc[_]
  psc.seccompProfile
  t := lower(psc.seccompProfile.type)
  allowed_seccomp[t]
}

# secret-like name helper without inline 'or'
secret_like(name, k) {
  startswith(name, k)
}
secret_like(name, k) {
  endswith(name, k)
}

# allowPrivilegeEscalation must be explicitly false
allow_priv_escal_false(c) {
  c.securityContext
  c.securityContext.allowPrivilegeEscalation == false
}

# readOnlyRootFilesystem must be explicitly true
read_only_fs_true(c) {
  c.securityContext
  c.securityContext.readOnlyRootFilesystem == true
}

########################################
# 1) Potential secrets in ENV (names)
########################################

deny[msg] {
  name := env_names[_]
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (starts with %s): %s", [k, name])
}

deny[msg] {
  name := env_names[_]
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (ends with %s): %s", [k, name])
}

deny[msg] {
  p := env_name_parts[_]
  suspicious_env_keys[p]
  msg := sprintf("Potential secret-like token in ENV name: %s", [p])
}

# Inline values for suspicious env names (suggest secretKeyRef)
warn[msg] {
  c := all_containers[_]
  c.env
  e := c.env[_]
  e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  secret_like(name, k)
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

warn[msg] {
  c := all_init_containers[_]
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

warn[msg] {
  c := all_containers[_]
  image_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for container %q image: %s", [c.name, c.image])
}
warn[msg] {
  c := all_init_containers[_]
  image_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for initContainer %q image: %s", [c.name, c.image])
}

########################################
# 3) Disallow package upgrade commands in command/args
########################################

deny[msg] {
  t := cmd_texts[_]
  c := pkg_update_commands[_]
  contains(t, lower(c))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [c])
}

########################################
# 4) Disallow hostPath volumes (node FS escape risk)
########################################

deny[msg] {
  ps := pod_specs[_]
  ps.volumes
  v := ps.volumes[_]
  v.hostPath
  msg := sprintf("hostPath volume is not allowed (name=%q, path=%q)", [v.name, v.hostPath.path])
}

########################################
# 5) Disallow sudo usage
########################################

deny[msg] {
  t := cmd_texts[_]
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

########################################
# 6) Require CPU/Memory requests and limits (containers & initContainers)
########################################

# Containers
deny[msg] {
  c := all_containers[_]
  not c.resources
  msg := sprintf("container %q missing resources", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("container %q missing resources.requests", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("container %q missing resources.limits", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny[msg] {
  c := all_containers[_]
  c.resources
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}

# initContainers
deny[msg] {
  c := all_init_containers[_]
  not c.resources
  msg := sprintf("initContainer %q missing resources", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.requests
  msg := sprintf("initContainer %q missing resources.requests", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.limits
  msg := sprintf("initContainer %q missing resources.limits", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.requests.cpu
  msg := sprintf("initContainer %q missing resources.requests.cpu", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.requests.memory
  msg := sprintf("initContainer %q missing resources.requests.memory", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.limits.cpu
  msg := sprintf("initContainer %q missing resources.limits.cpu", [c.name])
}
deny[msg] {
  c := all_init_containers[_]
  c.resources
  not c.resources.limits.memory
  msg := sprintf("initContainer %q missing resources.limits.memory", [c.name])
}

########################################
# 7) Require liveness & readiness probes (containers)
########################################

deny[msg] {
  c := all_containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny[msg] {
  c := all_containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

########################################
# 8) SecurityContext hardening
########################################

# Not privileged
deny[msg] {
  c := all_containers[_]
  c.securityContext
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}

# allowPrivilegeEscalation: false (explicit)
deny[msg] {
  c := all_containers[_]
  not allow_priv_escal_false(c)
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# readOnlyRootFilesystem: true (explicit)
deny[msg] {
  c := all_containers[_]
  not read_only_fs_true(c)
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

# runAsNonRoot true at container or pod level
deny[msg] {
  c := all_containers[_]
  not run_as_non_root_ok(c)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

# must not run as UID 0
deny[msg] {
  c := all_containers[_]
  is_root_user(c)
  msg := sprintf("container %q must not run as root user (runAsUser: 0)", [c.name])
}

# capabilities: disallow additions outside allow-list
deny[msg] {
  c := all_containers[_]
  ac := {cap | added_cap(c, cap); not allowed_add_caps[cap]}
  count(ac) > 0
  msg := sprintf("container %q adds disallowed Linux capabilities: %v", [c.name, ac])
}

# capabilities: recommend drop: ["ALL"]
warn[msg] {
  c := all_containers[_]
  not drops_all_caps(c)
  msg := sprintf("container %q should drop all capabilities (capabilities.drop: [\"ALL\"])", [c.name])
}

# seccomp: require RuntimeDefault or Localhost
deny[msg] {
  c := all_containers[_]
  not seccomp_ok(c)
  msg := sprintf("container %q must set a secure seccompProfile (RuntimeDefault or Localhost)", [c.name])
}

########################################
# 9) Disallow hostNetwork / hostPID / hostIPC
########################################

deny[msg] {
  ps := pod_specs[_]
  ps.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny[msg] {
  ps := pod_specs[_]
  ps.hostPID == true
  msg := "hostPID must be disabled"
}
deny[msg] {
  ps := pod_specs[_]
  ps.hostIPC == true
  msg := "hostIPC must be disabled"
}

########################################
# 10) Allowed image registries (strict allow-list)
########################################

deny[msg] {
  c := all_containers[_]
  not image_from_allowed_registry(c.image)
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}
deny[msg] {
  c := all_init_containers[_]
  not image_from_allowed_registry(c.image)
  msg := sprintf("initContainer %q image %q is not from an allowed registry", [c.name, c.image])
}