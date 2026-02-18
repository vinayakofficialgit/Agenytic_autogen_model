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

# Disallowed image tag(s)
image_tag_list := {
  "latest",
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
# Helpers
########################################

# Support single-doc, multi-doc, and kind: List
k8s_objs[obj] if {
  obj := input
  obj.kind
}
k8s_objs[obj] if {
  some i
  obj := input[i]
  obj.kind
}
k8s_objs[obj] if {
  input.kind == "List"
  obj := input.items[_]
}

# Extract PodSpecs from common workload kinds
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "pod";         ps := o.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "deployment";  ps := o.spec.template.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "statefulset"; ps := o.spec.template.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "daemonset";   ps := o.spec.template.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "replicaset";  ps := o.spec.template.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "job";         ps := o.spec.template.spec }
pod_specs[ps] if { o := k8s_objs[_]; lower(o.kind) == "cronjob";     ps := o.spec.jobTemplate.spec.template.spec }

# Containers and initContainers
all_containers[c] if { ps := pod_specs[_]; c := ps.containers[_] }
all_init_containers[c] if { ps := pod_specs[_]; c := ps.initContainers[_] }

# Pod-level securityContext (for runAs* and seccomp)
pod_sc[psc] if { ps := pod_specs[_]; psc := ps.securityContext }

# ENV names (lowercased)
env_names[name] if { c := all_containers[_]; e := c.env[_]; name := lower(e.name) }
env_names[name] if { c := all_init_containers[_]; e := c.env[_]; name := lower(e.name) }

# ENV name parts to catch tokens like FOO_API_KEY
env_name_parts[p] if {
  name := env_names[_]
  parts := regex.split("[_\\.-]", name)
  p := lower(parts[_])
  p != ""
}

# Aggregate command/args/lifecycle exec commands (lowercased).
# Split rules keep us safe when fields are missing.
cmd_texts[t] if { c := all_containers[_]; c.command; t := lower(concat(" ", c.command)) }
cmd_texts[t] if { c := all_containers[_]; c.args;    t := lower(concat(" ", c.args)) }
cmd_texts[t] if { c := all_init_containers[_]; c.command; t := lower(concat(" ", c.command)) }
cmd_texts[t] if { c := all_init_containers[_]; c.args;    t := lower(concat(" ", c.args)) }
cmd_texts[t] if { c := all_containers[_]; c.lifecycle.postStart.exec.command; t := lower(concat(" ", c.lifecycle.postStart.exec.command)) }
cmd_texts[t] if { c := all_containers[_]; c.lifecycle.preStop.exec.command;   t := lower(concat(" ", c.lifecycle.preStop.exec.command)) }
cmd_texts[t] if { c := all_init_containers[_]; c.lifecycle.postStart.exec.command; t := lower(concat(" ", c.lifecycle.postStart.exec.command)) }
cmd_texts[t] if { c := all_init_containers[_]; c.lifecycle.preStop.exec.command;   t := lower(concat(" ", c.lifecycle.preStop.exec.command)) }

# :latest or missing tag (unless pinned by digest)
image_is_latest_or_missing(img) if { endswith(lower(img), ":latest") }
image_is_latest_or_missing(img) if { not contains(img, ":"); not contains(img, "@sha256:") }

# Registry allow-list
image_from_allowed_registry(img) if {
  some p
  p := allowed_registries[_]
  startswith(lower(img), lower(p))
}

# Capability helpers (case-insensitive)
added_caps(c)[cap] if {
  a := c.securityContext.capabilities.add[_]
  cap := upper(a)
}
drops_all_caps(c) if { lower(c.securityContext.capabilities.drop[_]) == "all" }

# runAsNonRoot: true at container OR pod level
run_as_non_root_ok(c) if { c.securityContext.runAsNonRoot == true }
run_as_non_root_ok(c) if { psc := pod_sc[_]; psc.runAsNonRoot == true }

# runAsUser/root detection at container OR pod level
is_root_user(c) if { c.securityContext.runAsUser == 0 }
is_root_user(c) if { psc := pod_sc[_]; psc.runAsUser == 0 }

# seccomp: require RuntimeDefault or Localhost at container OR pod level
seccomp_ok(c) if {
  c.securityContext.seccompProfile.type
  t := lower(c.securityContext.seccompProfile.type)
  allowed_seccomp[t]
}
seccomp_ok(c) if {
  psc := pod_sc[_]
  psc.seccompProfile.type
  t := lower(psc.seccompProfile.type)
  allowed_seccomp[t]
}

########################################
# 1) Potential secrets in ENV (names)
########################################

deny contains msg if {
  name := env_names[_]
  k := suspicious_env_keys[_]
  startswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (starts with %s): %s", [k, name])
}

deny contains msg if {
  name := env_names[_]
  k := suspicious_env_keys[_]
  endswith(name, k)
  msg := sprintf("Potential secret-like ENV name found (ends with %s): %s", [k, name])
}

deny contains msg if {
  p := env_name_parts[_]
  suspicious_env_keys[p]
  msg := sprintf("Potential secret-like token in ENV name: %s", [p])
}

# Inline values for suspicious env names (suggest secretKeyRef)
warn contains msg if {
  c := all_containers[_]; e := c.env[_]; e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  (startswith(name, k) or endswith(name, k))
  msg := sprintf("ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}
warn contains msg if {
  c := all_init_containers[_]; e := c.env[_]; e.value
  name := lower(e.name)
  k := suspicious_env_keys[_]
  (startswith(name, k) or endswith(name, k))
  msg := sprintf("INIT ENV %q looks secret-like but uses inline value; prefer valueFrom.secretKeyRef", [e.name])
}

########################################
# 2) Disallow :latest (or missing tag) in images
########################################

warn contains msg if {
  c := all_containers[_]
  image_is_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for container %q image: %s", [c.name, c.image])
}
warn contains msg if {
  c := all_init_containers[_]
  image_is_latest_or_missing(c.image)
  msg := sprintf("Avoid :latest or missing tag for initContainer %q image: %s", [c.name, c.image])
}

########################################
# 3) Disallow package upgrade commands in command/args
########################################

deny contains msg if {
  t := cmd_texts[_]
  c := pkg_update_commands[_]
  contains(t, lower(c))
  msg := sprintf("Do not run package upgrade commands in containers: %s", [c])
}

########################################
# 4) Disallow hostPath volumes (node FS escape risk)
########################################

deny contains msg if {
  ps := pod_specs[_]
  v := ps.volumes[_]
  v.hostPath
  msg := sprintf("hostPath volume is not allowed (name=%q, path=%q)", [v.name, v.hostPath.path])
}

########################################
# 5) Disallow sudo usage
########################################

deny contains msg if {
  t := cmd_texts[_]
  contains(t, "sudo ")
  msg := sprintf("Avoid using 'sudo' in containers: %s", [t])
}

########################################
# 6) Require CPU/Memory requests and limits (all containers & initContainers)
########################################

deny contains msg if {
  c := all_containers[_]
  not c.resources.requests.cpu
  msg := sprintf("container %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  c := all_containers[_]
  not c.resources.requests.memory
  msg := sprintf("container %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  c := all_containers[_]
  not c.resources.limits.cpu
  msg := sprintf("container %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  c := all_containers[_]
  not c.resources.limits.memory
  msg := sprintf("container %q missing resources.limits.memory", [c.name])
}
deny contains msg if {
  c := all_init_containers[_]
  not c.resources.requests.cpu
  msg := sprintf("initContainer %q missing resources.requests.cpu", [c.name])
}
deny contains msg if {
  c := all_init_containers[_]
  not c.resources.requests.memory
  msg := sprintf("initContainer %q missing resources.requests.memory", [c.name])
}
deny contains msg if {
  c := all_init_containers[_]
  not c.resources.limits.cpu
  msg := sprintf("initContainer %q missing resources.limits.cpu", [c.name])
}
deny contains msg if {
  c := all_init_containers[_]
  not c.resources.limits.memory
  msg := sprintf("initContainer %q missing resources.limits.memory", [c.name])
}

########################################
# 7) Require liveness & readiness probes (containers)
########################################

deny contains msg if {
  c := all_containers[_]
  not c.livenessProbe
  msg := sprintf("container %q must define livenessProbe", [c.name])
}
deny contains msg if {
  c := all_containers[_]
  not c.readinessProbe
  msg := sprintf("container %q must define readinessProbe", [c.name])
}

########################################
# 8) SecurityContext hardening
########################################

# must NOT be privileged
deny contains msg if {
  c := all_containers[_]
  c.securityContext.privileged == true
  msg := sprintf("container %q must not run privileged", [c.name])
}

# must set allowPrivilegeEscalation: false
allow_priv_escal_false(c) {
  c.securityContext.allowPrivilegeEscalation == false
}
deny contains msg if {
  c := all_containers[_]
  not allow_priv_escal_false(c)
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation: false", [c.name])
}

# must set readOnlyRootFilesystem: true
deny contains msg if {
  c := all_containers[_]
  c.securityContext.readOnlyRootFilesystem != true
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem: true", [c.name])
}

# must run as non-root (container or pod level)
deny contains msg if {
  c := all_containers[_]
  not run_as_non_root_ok(c)
  msg := sprintf("container %q must set runAsNonRoot: true (at container or pod level)", [c.name])
}

# must not run as UID 0 (container or pod level)
deny contains msg if {
  c := all_containers[_]
  is_root_user(c)
  msg := sprintf("container %q must not run as root user (runAsUser: 0)", [c.name])
}

# capabilities: deny additions outside allow-list
deny contains msg if {
  c := all_containers[_]
  ac := {cap | cap := added_caps(c)[_]; not allowed_add_caps[cap]}
  count(ac) > 0
  msg := sprintf("container %q adds disallowed Linux capabilities: %v", [c.name, ac])
}

# capabilities: recommend drop: ["ALL"]
warn contains msg if {
  c := all_containers[_]
  not drops_all_caps(c)
  msg := sprintf("container %q should drop all capabilities (capabilities.drop: [\"ALL\"])", [c.name])
}

# seccomp: require RuntimeDefault or Localhost
deny contains msg if {
  c := all_containers[_]
  not seccomp_ok(c)
  msg := sprintf("container %q must set a secure seccompProfile (RuntimeDefault or Localhost)", [c.name])
}

########################################
# 9) Disallow hostNetwork / hostPID / hostIPC
########################################

deny contains msg if {
  ps := pod_specs[_]
  ps.hostNetwork == true
  msg := "hostNetwork must be disabled"
}
deny contains msg if {
  ps := pod_specs[_]
  ps.hostPID == true
  msg := "hostPID must be disabled"
}
deny contains msg if {
  ps := pod_specs[_]
  ps.hostIPC == true
  msg := "hostIPC must be disabled"
}

########################################
# 10) Allowed image registries (strict allow-list)
########################################

deny contains msg if {
  c := all_containers[_]
  not image_from_allowed_registry(c.image)
  msg := sprintf("container %q image %q is not from an allowed registry", [c.name, c.image])
}
deny contains msg if {
  c := all_init_containers[_]
  not image_from_allowed_registry(c.image)
  msg := sprintf("initContainer %q image %q is not from an allowed registry", [c.name, c.image])
}