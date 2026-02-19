resource "aws_eks_cluster" "demo" {
  name     = "enterprise-demo"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids = [aws_subnet.public1.id]
  }
}