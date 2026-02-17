package docker.security

########################################

Helpers

########################################

Dockerfile instructions array

instructions[i] := inst if {
inst := input[i]
}

Normalize command

cmd(inst) := lower(inst.Cmd)

########################################

1️⃣ Disallow :latest in FROM

########################################

deny contains msg if {
inst := instructions[_]
cmd(inst) == "from"
image := lower(inst.Value[0])
endswith(image, ":latest")
msg := sprintf("Base image must use pinned tag (no latest): %s", [inst.Value[0]])
}

########################################

2️⃣ Enforce Final USER Is Non-Root

########################################

Fail if no USER defined

deny contains msg if {
not final_user
msg := "Dockerfile must define a USER (non-root)"
}

Fail if final USER is root

deny contains msg if {
user := final_user
lower(user) == "root"
msg := "Final USER must not be root"
}

Fail if final USER is UID 0

deny contains msg if {
user := final_user
user == "0"
msg := "Final USER must not be UID 0"
}

Determine last USER instruction (Docker runtime behavior)

final_user := user if {
users := [
lower(inst.Value[0]) |
inst := instructions[_]
cmd(inst) == "user"
]
count(users) > 0
user := users[count(users)-1]
}

########################################

3️⃣ Disallow ADD (force COPY)

########################################

deny contains msg if {
inst := instructions[_]
cmd(inst) == "add"
msg := sprintf("Use COPY instead of ADD (found: ADD %v)", [inst.Value])
}

########################################

4️⃣ Disallow curl | bash

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

5️⃣ Require HEALTHCHECK

########################################

deny contains msg if {
not has_healthcheck
msg := "Dockerfile must define HEALTHCHECK"
}

has_healthcheck if {
inst := instructions[_]
cmd(inst) == "healthcheck"
}