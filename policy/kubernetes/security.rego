package k8s.security

########################################
# Default
########################################

default deny := []

########################################
# Helpers
########################################

is_deployment if {
  lower(input.kind) == "deployment"
}

containers := input.spec.template.spec.containers

########################################
# 1️⃣ Enforce runAsNonRoot
########################################

deny contains msg if {
  is_deployment
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Deployment must set securityContext.runAsNonRoot=true"
}

########################################
# 2️⃣ Require resource limits
########################################

deny contains msg if {
  is_deployment
  some c
  container := containers[c]
  not container.resources.limits
  msg := sprintf("Container %q must define resource limits", [container.name])
}

########################################
# 3️⃣ Disallow privileged containers
########################################

deny contains msg if {
  is_deployment
  some c
  container := containers[c]
  container.securityContext.privileged == true
  msg := sprintf("Container %q must not run privileged", [container.name])
}