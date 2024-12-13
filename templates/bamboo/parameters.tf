variable "parameters" {
  type = object({
    network_stack = string
    stack_name = string
    db_subnet_ids= list(string)
    vpc_id=string
    private_subnet_ids=list(string)
  })
}
