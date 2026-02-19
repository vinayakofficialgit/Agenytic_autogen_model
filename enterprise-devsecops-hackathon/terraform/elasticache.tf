resource "aws_elasticache_cluster" "memcached" {
  cluster_id      = "demo-cache"
  engine          = "memcached"
  node_type       = "cache.t2.micro"
  num_cache_nodes = 1
}