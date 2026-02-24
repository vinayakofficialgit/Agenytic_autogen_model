# SECURITY GROUP WITH WIDE OPEN INGRESS (OPTIONAL)
resource "aws_security_group" "wide_open" {
  name        = "${var.project}-wide-open-sg"
  description = "INTENTIONALLY wide-open SG for demo"
  vpc_id      = "vpc-12345678"   # any placeholder; not used for scans

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌
  }

  ingress {
    description = "App from anywhere"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ❌
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # ❌ overly broad
  }

  tags = {
    Purpose = "insecure-demo"
  }
}