resource "aws_s3_bucket" "bad" {
  bucket = "public-bucket-demo"
  acl    = "public-read"
}