package docker.security

# Rule: Base image must be from an approved list
approved_base_images = {
    "alpine:3.18",
    "ubuntu:22.04",
    "debian:12"
}

deny[msg] {
    input[0].Instruction == "FROM"
    base := input[0].Value
    not approved_base_images[base]
    msg := sprintf("Base image '%s' is not approved. Use one of: %v", [base, approved_base_images])
}

# Rule: Avoid using 'latest' tag
deny[msg] {
    input[i].Instruction == "FROM"
    endswith(input[i].Value, ":latest")
    msg := "Avoid using 'latest' tag for base images."
}

# Rule: Ensure no root user is used
deny[msg] {
    input[i].Instruction == "USER"
    input[i].Value == "root"
    msg := "Do not run containers as root user."
}