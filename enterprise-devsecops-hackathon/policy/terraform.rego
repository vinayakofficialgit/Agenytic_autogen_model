package terraform.security

deny[msg] {
  input.resource_type == "aws_security_group"
  input.config.ingress[_].cidr_blocks[_] == "10.0.0.0/16"
  msg := "Security group open to the world"
}