package kubernetes.security

########################################
# Safe Helpers
########################################

# True only for Deployment objects
is_deployment if {
  lower(input.kind) == "deployment"
}

# Safe access to pod spec
pod_spec := spec if {
  is_deployment
  spec := input.spec.template.spec
}

# Safe container iterator
containers[c] := container if {
  pod_spec
  container := pod_spec.containers[c]
}

########################################
# 1️⃣ Require runAsNonRoot (Pod level)
########################################

deny contains msg if {
  pod_spec
  not pod_spec.securityContext.runAsNonRoot
  msg := "Deployment must set securityContext.runAsNonRoot=true"
}

########################################
# 2️⃣ Require container resource limits
########################################

deny contains msg if {
  container := containers[_]
  not container.resources
  msg := sprintf("Container %q must define resources block", [container.name])
}

deny contains msg if {
  container := containers[_]
  container.resources
  not container.resources.limits
  msg := sprintf("Container %q must define resource limits", [container.name])
}

########################################
# 3️⃣ Disallow privileged containers
########################################

deny contains msg if {
  container := containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Container %q must not run privileged", [container.name])
}

########################################
# 4️⃣ Disallow :latest image tag
########################################

deny contains msg if {
  container := containers[_]
  endswith(lower(container.image), ":latest")
  msg := sprintf("Container %q must not use latest tag", [container.name])
}

########################################
# 5️⃣ Require livenessProbe
########################################

deny contains msg if {
  container := containers[_]
  not container.livenessProbe
  msg := sprintf("Container %q must define livenessProbe", [container.name])
}

########################################
# 6️⃣ Require readinessProbe
########################################

deny contains msg if {
  container := containers[_]
  not container.readinessProbe
  msg := sprintf("Container %q must define readinessProbe", [container.name])
}