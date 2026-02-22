resource "aws_s3_bucket" "demo" {
  bucket = "demo-vuln-bucket"
  acl    = "public-read"
}