
package k8s.security

default deny = []

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot
  msg := "Deployment must set securityContext.runAsNonRoot=true"
}

deny[msg] {
  input.kind == "Deployment"
  some c
  container := input.spec.template.spec.containers[c]
  not container.resources.limits
  msg := sprintf("Container %q must define resource limits", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  some c
  container := input.spec.template.spec.containers[c]
  container.securityContext.privileged == true
  msg := sprintf("Container %q must not run privileged", [container.name])
}
