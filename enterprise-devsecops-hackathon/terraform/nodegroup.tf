resource "aws_eks_node_group" "demo_nodes" {
  cluster_name    = aws_eks_cluster.demo.name
  node_group_name = "demo-nodes"
  node_role_arn   = aws_iam_role.eks_role.arn
  subnet_ids      = [aws_subnet.public1.id]

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }
}