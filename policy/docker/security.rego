package docker.security

########################################
# Helpers
########################################

# Gather instructions whether input is flat array or nested in Stages/Commands
instructions[inst] {
  some i
  inst := input[i]
  inst.Cmd
}

instructions[inst] {
  some s, c
  inst := input.Stages[s].Commands[c]
  inst.Cmd
}

# Normalize command name
cmd(inst) := lower(inst.Cmd)

# Normalize the first argument (works for string or array Value)
first_arg(inst) := v {
  is_array(inst.Value)
  v := lower(tostring(inst.Value[0]))
} else := v {
  not is_array(inst.Value)
  v := lower(tostring(inst.Value))
}

########################################
# 1️⃣ Disallow :latest in FROM
########################################

deny contains msg if {
  inst := instructions[_]
  cmd(inst) == "from"
  image := first_arg(inst)
  endswith(image, ":latest")
  msg := sprintf("Base image must use pinned tag (no latest): %s", [first_arg_raw(inst)])
}

# keep raw string for better message if available
first_arg_raw(inst) := out {
  is_array(inst.Value)
  out := inst.Value[0]
} else := out {
  not is_array(inst.Value)
  out := inst.Value
}

########################################
# 2️⃣ Require non-root USER
########################################

# Fail if there is no USER set to a non-root value
deny contains msg if {
  not has_non_root_user
  msg := "Dockerfile must set a non-root USER"
}

has_non_root_user if {
  inst := instructions[_]
  cmd(inst) == "user"
  u := first_arg(inst)
  u != "root"
  u != "0"
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
  val := lower(
    (is_array(inst.Value); concat(" ", inst.Value)) 
    else tostring(inst.Value)
  )
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