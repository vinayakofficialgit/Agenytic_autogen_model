resource "aws_db_instance" "demo" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "admin123"
  publicly_accessible  = true
  skip_final_snapshot  = true
}