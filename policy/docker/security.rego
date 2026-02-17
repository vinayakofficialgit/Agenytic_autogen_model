package docker.security

########################################

# Config

########################################

suspicious_env_keys := {
"passwd",
"password",
"secret",
"key",
"access",
"api_key",
"apikey",
"token",
}

pkg_update_commands := {
"apk upgrade",
"apt-get upgrade",
"dist-upgrade",
}

image_tag_list := {
"latest",
}

########################################

# Helpers

########################################

cmd(inst) := lower(inst.Cmd)
inst_text(inst) := lower(concat(" ", inst.Value))

env_entries := [lower(e) |
inst := input[_]
cmd(inst) == "env"
e := inst.Value[_]
]


env_parts := [p |
e := env_entries[_]
parts := regex.split("[ :=-]", e)
p := lower(parts[_])
p != ""
]

########################################

# 1) Potential secrets in ENV

########################################

deny contains msg if {
e := env_entries[_]
k := suspicious_env_keys[_]
startswith(e, k)
msg := sprintf("Potential secret in ENV found: %s", [e])
}

deny contains msg if {
e := env_entries[_]
k := suspicious_env_keys[_]
endswith(e, k)
msg := sprintf("Potential secret in ENV found: %s", [e])
}

deny contains msg if {
p := env_parts[_]
p == suspicious_env_keys[_]
msg := sprintf("Potential secret-like key in ENV found (part=%s)", [p])
}

########################################

# 2) Disallow :latest (or missing tag) in FROM

########################################

warn contains msg if {
inst := input[_]
cmd(inst) == "from"

img := inst.Value[0]
parts := split(img, ":")

count(parts) == 1
msg := sprintf("Image tag missing (defaults to latest): %s", [img])
}

warn contains msg if {
inst := input[_]
cmd(inst) == "from"

img := lower(inst.Value[0])
endswith(img, ":latest")

msg := sprintf("Do not use latest tag with image: %s", [inst.Value[0]])
}

########################################

# 3) Disallow package upgrade commands in RUN

########################################

deny contains msg if {
inst := input[_]
cmd(inst) == "run"
val := inst_text(inst)

c := pkg_update_commands[_]
contains(val, c)

msg := sprintf("Do not use upgrade commands in Dockerfile RUN: %s", [val])
}

########################################

# 4) Disallow ADD (use COPY)

########################################

deny contains msg if {
inst := input[_]
cmd(inst) == "ADD"
msg := sprintf("Use COPY instead of ADD: %s", [concat(" ", inst.Value)])
}

########################################

# 5) Disallow sudo usage

########################################

deny contains msg if {
inst := input[_]
cmd(inst) == "run"
val := inst_text(inst)
contains(val, "sudo")
msg := sprintf("Avoid using 'sudo' command: %s", [val])
}