package terraform.security

deny[msg] {
  input.resource_type == "aws_security_group"
  input.config.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg := "Security group open to the world"
}