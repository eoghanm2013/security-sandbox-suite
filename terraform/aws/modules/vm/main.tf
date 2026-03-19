variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

# --- VM Finding: EC2 Instance with Vulnerable Packages ---

data "aws_ami" "ubuntu_2004" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "vm_instance" {
  name        = "${var.name_prefix}-vm-sg"
  description = "Security group for VM scanning target"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-vm-sg" }
}

resource "aws_instance" "vulnerable" {
  ami           = data.aws_ami.ubuntu_2004.id
  instance_type = "t3.micro"
  subnet_id     = var.subnet_id

  vpc_security_group_ids = [aws_security_group.vm_instance.id]

  user_data = <<-USERDATA
    #!/bin/bash
    # Install Datadog Agent for host vulnerability scanning
    # The agent will detect the outdated base packages in Ubuntu 20.04

    # Pin some known-vulnerable packages to prevent auto-update
    apt-mark hold openssl libssl1.1 curl libcurl4 sudo

    # Install additional vulnerable packages
    apt-get update
    apt-get install -y --allow-downgrades \
      imagemagick \
      ghostscript \
      libxml2 \
      openssh-server

    echo "VM scanning target ready" > /tmp/sandbox-vm-ready
  USERDATA

  tags = {
    Name = "${var.name_prefix}-vulnerable-host"
    vm   = "true"
  }
}

# --- VM Finding: ECR Repository with Vulnerable Base Image ---

resource "aws_ecr_repository" "vulnerable" {
  name                 = "${var.name_prefix}-vulnerable-images"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = { vm = "true" }
}

output "instance_id" {
  value = aws_instance.vulnerable.id
}

output "ecr_repo_url" {
  value = aws_ecr_repository.vulnerable.repository_url
}
