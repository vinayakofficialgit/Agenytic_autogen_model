
package docker.security

deny[msg] {
  some i
  input[i].Cmd == "from"
  endswith(lower(input[i].Value[0]), ":latest")
  msg := sprintf("Use pinned base image tags (no 'latest'): %s", [input[i].Value[0]])
}

deny[msg] {
  not user_non_root
  msg := "Dockerfile must set a non-root USER"
}

user_non_root {
  some i
  input[i].Cmd == "user"
  lower(input[i].Value[0]) != "root"
}

deny[msg] {
  some i
  input[i].Cmd == "add"
  msg := "Use COPY instead of ADD"
}
