package docker.security

########################################
# Helpers
########################################

# Collect instructions whether input is flat array or nested under Stages/Commands
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

# Get the first argument (lowercased) regardless of string/array
first_arg(inst) := v {
  is_array(inst.Value)
  v := lower(tostring(inst.Value[0]))
} else := v {
  not is_array(inst.Value)
  v := lower(tostring(inst.Value))
}

# For display: raw first arg (unmodified)
first_arg_raw(inst) := out {
  is_array(inst.Value)
  out := inst.Value[0]
} else := out {
  not is_array(inst.Value)
  out := inst.Value
}

# Join all value tokens into a single lowercased string for RUN analysis
# (handles either an array or a string)
value_as_text(inst) := v {
  is_array(inst.Value)
  # concat expects array of strings; ensure tostring on each element
  parts := [ tostring(x) | x := inst.Value[_] ]
  v := lower(concat(" ", parts))
} else := v {
  not is_array(inst.Value)
  v := lower(tostring(inst.Value))
}

########################################
# 1️⃣ Disallow :latest in FROM
########################################

deny[msg] {
  inst := instructions[_]
  cmd(inst) == "from"
  image := first_arg(inst)
  endswith(image, ":latest")
  msg := sprintf("Base image must use pinned tag (no latest): %s", [ first_arg_raw(inst) ])
}

########################################
# 2️⃣ Require non-root USER
########################################

# Explicitly deny if USER is root/0
deny[msg] {
  inst := instructions[_]
  cmd(inst) == "user"
  u := first_arg(inst)
  u == "root" or u == "0"
  msg := "USER must not be root"
}

# Also require that Dockerfile sets a non-root USER somewhere
deny[msg] {
  not has_non_root_user
  msg := "Dockerfile must set a non-root USER"
}

has_non_root_user {
  inst := instructions[_]
  cmd(inst) == "user"
  u := first_arg(inst)
  u != "root"
  u != "0"
}

########################################
# 3️⃣ Disallow ADD (force COPY)
########################################

deny[msg] {
  inst := instructions[_]
  cmd(inst) == "add"
  msg := sprintf("Use COPY instead of ADD (found: ADD %v)", [inst.Value])
}

########################################
# 4️⃣ Disallow curl | bash pattern
########################################

deny[msg] {
  inst := instructions[_]
  cmd(inst) == "run"
  val := value_as_text(inst)
  contains(val, "curl")
  contains(val, "|")
  msg := "Avoid curl | bash pattern. Use verified package sources instead."
}

########################################
# 5️⃣ Require HEALTHCHECK
########################################

deny[msg] {
  not has_healthcheck
  msg := "Dockerfile must define HEALTHCHECK"
}

has_healthcheck {
  inst := instructions[_]
  cmd(inst) == "healthcheck"
}