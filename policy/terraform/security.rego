package terraform.security

########################################
# Default
########################################

default deny := []

########################################
# Helpers
########################################

resources := input.resource_changes

is_create_or_update(rc) if {
  rc.change.actions[_] == "create"
} else if {
  rc.change.actions[_] == "update"
}

########################################
# 1️⃣ Block Public S3 Buckets
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_s3_bucket"
  is_create_or_update(rc)

  rc.change.after.acl == "public-read"
  msg := sprintf("S3 bucket %q must not be public", [rc.name])
}

########################################
# 2️⃣ Block 0.0.0.0/0 in Security Groups
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_security_group"
  is_create_or_update(rc)

  ingress := rc.change.after.ingress[_]
  ingress.cidr_blocks[_] == "0.0.0.0/0"

  msg := sprintf("Security group %q allows 0.0.0.0/0 ingress", [rc.name])
}

########################################
# 3️⃣ RDS must not be publicly accessible
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_db_instance"
  is_create_or_update(rc)

  rc.change.after.publicly_accessible == true
  msg := sprintf("RDS instance %q must not be publicly accessible", [rc.name])
}

########################################
# 4️⃣ Enforce EBS encryption
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_ebs_volume"
  is_create_or_update(rc)

  not rc.change.after.encrypted
  msg := sprintf("EBS volume %q must be encrypted", [rc.name])
}

########################################
# 5️⃣ Enforce required tags
########################################

required_tags := {"Environment", "Owner", "Project"}

deny contains msg if {
  rc := resources[_]
  is_create_or_update(rc)

  tag := required_tags[_]

  not rc.change.after.tags[tag]
  msg := sprintf("Resource %q missing required tag %q", [rc.name, tag])
}

########################################
# 6️⃣ Enforce IMDSv2 on EC2
########################################

deny contains msg if {
  rc := resources[_]
  rc.type == "aws_instance"
  is_create_or_update(rc)

  rc.change.after.metadata_options.http_tokens != "required"
  msg := sprintf("EC2 instance %q must enforce IMDSv2", [rc.name])
}