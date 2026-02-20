
resource "aws_security_group" "open_demo" {
  name        = "open-demo"
  description = "open ingress"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}