package terraform.security

default deny = []

# ============================================================
# Helper: Required Tags
# ============================================================
required_tags := {"Environment", "Owner", "Project"}

missing_tags(resource) {
  not resource.tags
}

missing_tags(resource) {
  some t
  required_tags[t]
  not resource.tags[t]
}

# ============================================================
# 1️⃣ Block Public S3 Buckets
# ============================================================
deny[msg] {
  resource := input.resource.aws_s3_bucket[_]
  resource.acl == "public-read"
  msg := sprintf("S3 bucket %q must not be public-read", [resource.bucket])
}

deny[msg] {
  resource := input.resource.aws_s3_bucket[_]
  resource.acl == "public-read-write"
  msg := sprintf("S3 bucket %q must not be public-read-write", [resource.bucket])
}

# Require versioning
deny[msg] {
  resource := input.resource.aws_s3_bucket[_]
  not resource.versioning.enabled
  msg := sprintf("S3 bucket %q must enable versioning", [resource.bucket])
}

# Require encryption
deny[msg] {
  resource := input.resource.aws_s3_bucket[_]
  not resource.server_side_encryption_configuration
  msg := sprintf("S3 bucket %q must enable server-side encryption", [resource.bucket])
}

# ============================================================
# 2️⃣ Security Groups - No Open World on Sensitive Ports
# ============================================================
deny[msg] {
  sg := input.resource.aws_security_group[_]
  rule := sg.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port == 22
  msg := sprintf("Security group %q must not allow SSH from 0.0.0.0/0", [sg.name])
}

deny[msg] {
  sg := input.resource.aws_security_group[_]
  rule := sg.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port == 3389
  msg := sprintf("Security group %q must not allow RDP from 0.0.0.0/0", [sg.name])
}

deny[msg] {
  sg := input.resource.aws_security_group[_]
  rule := sg.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port == 0
  rule.to_port == 0
  msg := sprintf("Security group %q must not allow all traffic from 0.0.0.0/0", [sg.name])
}

# ============================================================
# 3️⃣ EC2 Hardening
# ============================================================
deny[msg] {
  instance := input.resource.aws_instance[_]
  instance.associate_public_ip_address == true
  msg := sprintf("EC2 instance %q must not have public IP", [instance.tags.Name])
}

deny[msg] {
  instance := input.resource.aws_instance[_]
  not instance.root_block_device.encrypted
  msg := sprintf("EC2 instance %q must enable EBS encryption", [instance.tags.Name])
}

# ============================================================
# 4️⃣ RDS Hardening
# ============================================================
deny[msg] {
  db := input.resource.aws_db_instance[_]
  db.publicly_accessible == true
  msg := sprintf("RDS instance %q must not be publicly accessible", [db.identifier])
}

deny[msg] {
  db := input.resource.aws_db_instance[_]
  not db.storage_encrypted
  msg := sprintf("RDS instance %q must enable storage encryption", [db.identifier])
}

# ============================================================
# 5️⃣ IAM Policy Restrictions
# ============================================================
deny[msg] {
  policy := input.resource.aws_iam_policy[_]
  contains(lower(policy.policy), "\"action\":\"*\"")
  contains(lower(policy.policy), "\"resource\":\"*\"")
  msg := sprintf("IAM policy %q must not allow *:* permissions", [policy.name])
}

deny[msg] {
  role := input.resource.aws_iam_role[_]
  contains(lower(role.assume_role_policy), "\"effect\":\"allow\"")
  contains(lower(role.assume_role_policy), "\"principal\":\"*\"")
  msg := sprintf("IAM role %q must not allow wildcard principal", [role.name])
}

# ============================================================
# 6️⃣ Load Balancer Security
# ============================================================
deny[msg] {
  lb := input.resource.aws_lb_listener[_]
  lb.protocol == "HTTP"
  msg := sprintf("Load balancer listener %q must use HTTPS", [lb.port])
}

# ============================================================
# 7️⃣ Enforce Required Tags on Critical Resources
# ============================================================
deny[msg] {
  resource := input.resource.aws_instance[_]
  missing_tags(resource)
  msg := sprintf("EC2 instance %q missing required tags", [resource.tags.Name])
}

deny[msg] {
  resource := input.resource.aws_s3_bucket[_]
  missing_tags(resource)
  msg := sprintf("S3 bucket %q missing required tags", [resource.bucket])
}

deny[msg] {
  resource := input.resource.aws_db_instance[_]
  missing_tags(resource)
  msg := sprintf("RDS instance %q missing required tags", [resource.identifier])
}