module network {
  source = "./templates/network"
  region = "ap-south-1"
  number_of_azs = 3
}

module "bamboo" {
  depends_on = [module.network]
  source = "./templates/bamboo"
  parameters = {
    network_stack =  module.network.outputs.network_stack
    stack_name = "${module.network.outputs.network_stack}-Bamboo"
    db_subnet_ids= module.network.outputs.db_subnet_ids
    vpc_id=module.network.outputs.vpcId
    private_subnet_ids=module.network.outputs.private_subnet_ids
  }
}