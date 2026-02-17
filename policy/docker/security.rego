package docker.security

########################################
# Deny latest tag in FROM
########################################

deny[msg] if {
  some i
  input[i].Cmd == "from"
  endswith(lower(input[i].Value[0]), ":latest")
  msg := sprintf("Use pinned base image tags (no 'latest'): %s", [input[i].Value[0]])
}

########################################
# Require non-root USER
########################################

deny[msg] if {
  not user_non_root
  msg := "Dockerfile must set a non-root USER"
}

user_non_root if {
  some i
  input[i].Cmd == "user"
  lower(input[i].Value[0]) != "root"
}

########################################
# Disallow ADD
########################################

deny[msg] if {
  some i
  input[i].Cmd == "add"
  msg := "Use COPY instead of ADD"
}