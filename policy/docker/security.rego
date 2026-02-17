package docker.security

########################################
# Safe Helpers
########################################

# Dockerfile input is expected as array of instructions
instructions[i] := inst if {
  inst := input[i]
}

# Normalize command
cmd(inst) := lower(inst.Cmd)

########################################
# 1️⃣ Disallow :latest in FROM
########################################

deny contains msg if {
  inst := instructions[_]
  cmd(inst) == "from"

  image := lower(inst.Value[0])
  endswith(image, ":latest")

  msg := sprintf("Base image must use pinned tag (no latest): %s", [inst.Value[0]])
}

########################################
# 2️⃣ Require non-root USER
########################################

deny contains msg if {
  not has_non_root_user
  msg := "Dockerfile must set a non-root USER"
}

has_non_root_user if {
  inst := instructions[_]
  cmd(inst) == "user"

  user := lower(inst.Value[0])
  user != "root"
  user != "0"
}

########################################
# 3️⃣ Disallow ADD (force COPY)
########################################

deny contains msg if {
  inst := instructions[_]
  cmd(inst) == "add"

  msg := sprintf("Use COPY instead of ADD (found: ADD %v)", [inst.Value])
}

########################################
# 4️⃣ Disallow curl | bash pattern
########################################

deny contains msg if {
  inst := instructions[_]
  cmd(inst) == "run"

  val := lower(concat(" ", inst.Value))
  contains(val, "curl")
  contains(val, "|")

  msg := "Avoid curl | bash pattern. Use verified package sources instead."
}

########################################
# 5️⃣ Require HEALTHCHECK
########################################

deny contains msg if {
  not has_healthcheck
  msg := "Dockerfile must define HEALTHCHECK"
}

has_healthcheck if {
  inst := instructions[_]
  cmd(inst) == "healthcheck"
}