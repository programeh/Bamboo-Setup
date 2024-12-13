locals {
  region_map = {
    "ap-south-1"   = "in1"
    "eu-west-1"   = "eu1"
  }
}

output "outputs" {
  value = {
    network_stack=local.region_map[var.region]
    db_subnet_ids= module.bamboo-vpc.database_subnets
    private_subnet_ids= module.bamboo-vpc.private_subnets
    vpcId=module.bamboo-vpc.vpc_id
  }
}