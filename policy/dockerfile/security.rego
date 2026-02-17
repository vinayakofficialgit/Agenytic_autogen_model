package docker.security

default deny = []

# ------------------------------------------------------------
# 1. Disallow :latest tag
# ------------------------------------------------------------
deny[msg] {
  some i
  input[i].Cmd == "from"
  image := lower(input[i].Value[0])
  endswith(image, ":latest")
  msg := sprintf("Use pinned base image tags (no 'latest'): %s", [image])
}

# ------------------------------------------------------------
# 2. Require pinned digest (optional strict mode)
# ------------------------------------------------------------
deny[msg] {
  some i
  input[i].Cmd == "from"
  image := input[i].Value[0]
  not contains(image, "@sha256:")
  msg := sprintf("Base image should use immutable digest (sha256): %s", [image])
}

# ------------------------------------------------------------
# 3. Require non-root user
# ------------------------------------------------------------
deny[msg] {
  not user_non_root
  msg := "Dockerfile must set a non-root USER"
}

user_non_root {
  some i
  input[i].Cmd == "user"
  lower(input[i].Value[0]) != "root"
}

# ------------------------------------------------------------
# 4. Disallow ADD (prefer COPY)
# ------------------------------------------------------------
deny[msg] {
  some i
  input[i].Cmd == "add"
  msg := "Use COPY instead of ADD"
}

# ------------------------------------------------------------
# 5. Prevent privileged package managers without cleanup
# ------------------------------------------------------------
deny[msg] {
  some i
  input[i].Cmd == "run"
  contains(lower(concat(" ", input[i].Value)), "apt-get install")
  not contains(lower(concat(" ", input[i].Value)), "rm -rf /var/lib/apt/lists")
  msg := "apt-get install must clean cache to reduce attack surface"
}

# ------------------------------------------------------------
# 6. Disallow curl | bash pattern
# ------------------------------------------------------------
deny[msg] {
  some i
  input[i].Cmd == "run"
  val := lower(concat(" ", input[i].Value))
  contains(val, "curl") 
  contains(val, "|")
  contains(val, "sh")
  msg := "Avoid piping curl directly to shell (curl | sh)"
}

# ------------------------------------------------------------
# 7. Require HEALTHCHECK
# ------------------------------------------------------------
deny[msg] {
  not healthcheck_defined
  msg := "Dockerfile should define HEALTHCHECK"
}

healthcheck_defined {
  some i
  input[i].Cmd == "healthcheck"
}