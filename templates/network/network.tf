locals {
  selected_azs = slice(data.aws_availability_zones.available_az.names, 0, var.number_of_azs)
}


data "aws_availability_zones" "available_az" {
  state = "available"
}

module "bamboo-vpc" {
  source  = "terraform-aws-modules/vpc/aws"

  name                 = "bamboo-VPC"
  cidr                 = "10.12.0.0/20"
  azs                  = local.selected_azs
  private_subnets      = ["10.12.0.0/28", "10.12.0.32/28", "10.12.0.64/28"]
  public_subnets       = ["10.12.1.0/28", "10.12.1.32/28", "10.12.1.64/28"]
  create_database_subnet_group=true
  manage_default_security_group = false
  manage_default_route_table=false
  manage_default_network_acl=false
  database_subnets    = ["10.12.2.0/28", "10.12.2.32/28","10.12.2.64/28"]
  enable_dns_hostnames = true
}

module "bamboo-nat" {
  source  = "int128/nat-instance/aws"
  version = "2.1.0"

  name                        = "bamboo-NAT"
  vpc_id                      = module.bamboo-vpc.vpc_id
  public_subnet               = module.bamboo-vpc.public_subnets[0]
  private_subnets_cidr_blocks = module.bamboo-vpc.private_subnets_cidr_blocks
  private_route_table_ids     = module.bamboo-vpc.private_route_table_ids
}

resource "aws_eip" "nat" {
  network_interface = module.bamboo-nat.eni_id
  tags = {
    "Name" = "nat-instance-bamboo"
  }
}