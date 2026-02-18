package main

# Aggregate DENY from all policy packages

deny contains msg if {
msg := data.docker.security.deny[_]
}

deny contains msg if {
msg := data.kubernetes.security.deny[_]
}

deny contains msg if {
msg := data.terraform.security.deny[_]
}

# Aggregate WARN from all policy packages (if you use warn rules)

warn contains msg if {
msg := data.docker.security.warn[_]
}

warn contains msg if {
msg := data.kubernetes.security.warn[_]
}

warn contains msg if {
msg := data.terraform.security.warn[_]
}