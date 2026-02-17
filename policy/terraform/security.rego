package terraform.security

########################################
# Safe Helpers
########################################

# Safe resource iterator
resources[r] := rc if {
  rc := input.resource_changes[r]
}

# Only evaluate create/update operations
is_create_or_update(rc) if {
  rc.change.actions[_] == "create"
} else if {
  rc.change.actions[_] == "update"
}

# Safe access to "after" block
after(rc) := obj if {
  is_create_or_update(rc)
  obj := rc.change.after
  obj != null
}

########################################
# 1️⃣ Block Public S3 Buckets
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_s3_bucket"
  obj := after(rc)

  obj.acl == "public-read"

  msg := sprintf("S3 bucket %q must not be public", [rc.name])
}

########################################
# 2️⃣ Block 0.0.0.0/0 Ingress
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_security_group"
  obj := after(rc)

  ingress := obj.ingress[_]
  ingress.cidr_blocks[_] == "0.0.0.0/0"

  msg := sprintf("Security group %q allows 0.0.0.0/0 ingress", [rc.name])
}

########################################
# 3️⃣ Block Public RDS
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_db_instance"
  obj := after(rc)

  obj.publicly_accessible == true

  msg := sprintf("RDS instance %q must not be publicly accessible", [rc.name])
}

########################################
# 4️⃣ Enforce EBS Encryption
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_ebs_volume"
  obj := after(rc)

  not obj.encrypted

  msg := sprintf("EBS volume %q must be encrypted", [rc.name])
}

########################################
# 5️⃣ Enforce Required Tags (Null-Safe)
########################################

required_tags := {"Environment", "Owner", "Project"}

deny contains msg if {
  rc := resources[_]
  obj := after(rc)

  tag := required_tags[_]

  not has_tag(obj, tag)

  msg := sprintf("Resource %q missing required tag %q", [rc.name, tag])
}

has_tag(obj, tag) if {
  obj.tags[tag]
}

########################################
# 6️⃣ Enforce IMDSv2 on EC2
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_instance"
  obj := after(rc)

  obj.metadata_options.http_tokens != "required"

  msg := sprintf("EC2 instance %q must enforce IMDSv2", [rc.name])
}