terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      creator = var.creator
      team    = var.team
      service = "security-sandbox-suite"
      project = "sandbox-suite"
    }
  }
}

module "cspm" {
  source     = "./modules/cspm"
  name_prefix = var.name_prefix
}

module "ciem" {
  source     = "./modules/ciem"
  name_prefix = var.name_prefix
}

module "vm" {
  source     = "./modules/vm"
  name_prefix = var.name_prefix
  vpc_id     = module.cspm.vpc_id
  subnet_id  = module.cspm.subnet_id
}

module "siem" {
  source     = "./modules/siem"
  name_prefix = var.name_prefix
  vpc_id     = module.cspm.vpc_id
}
