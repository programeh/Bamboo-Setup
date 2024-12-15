provider "aws" {
  region  = "ap-south-1" # Specify your desired AWS region
  profile = "default"    # Specify your AWS CLI profile (optional)
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.54.1"
    }
  }
}