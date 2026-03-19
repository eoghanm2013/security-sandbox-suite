variable "name_prefix" {
  type = string
}

data "aws_availability_zones" "available" {
  state = "available"
}

# --- VPC (shared by other modules) ---

resource "aws_vpc" "sandbox" {
  cidr_block           = "10.99.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_subnet" "sandbox" {
  vpc_id            = aws_vpc.sandbox.id
  cidr_block        = "10.99.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "${var.name_prefix}-subnet" }
}

resource "aws_internet_gateway" "sandbox" {
  vpc_id = aws_vpc.sandbox.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

# --- CSPM Finding: Public S3 Bucket ---

resource "aws_s3_bucket" "public_bucket" {
  bucket        = "${var.name_prefix}-public-misconfig"
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-public-bucket", cspm = "true" }
}

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket                  = aws_s3_bucket.public_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_bucket.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.public_bucket]
}

# --- CSPM Finding: Overly Permissive Security Group ---

resource "aws_security_group" "open_ssh" {
  name        = "${var.name_prefix}-open-ssh"
  description = "CSPM finding: SSH open to the world"
  vpc_id      = aws_vpc.sandbox.id

  ingress {
    description = "SSH from anywhere (intentional misconfiguration)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All traffic from anywhere (intentional misconfiguration)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-open-sg", cspm = "true" }
}

# --- CSPM Finding: Unencrypted EBS Volume ---

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  encrypted         = false
  tags              = { Name = "${var.name_prefix}-unencrypted-ebs", cspm = "true" }
}

# --- CSPM Finding: S3 Bucket Without Versioning ---

resource "aws_s3_bucket" "no_versioning" {
  bucket        = "${var.name_prefix}-no-versioning"
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-no-versioning", cspm = "true" }
}

# --- CSPM Finding: S3 Bucket Without Server-Side Encryption ---

resource "aws_s3_bucket" "no_encryption" {
  bucket        = "${var.name_prefix}-no-encryption"
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-no-encryption", cspm = "true" }
}

# Outputs for other modules
output "vpc_id" {
  value = aws_vpc.sandbox.id
}

output "subnet_id" {
  value = aws_subnet.sandbox.id
}

output "public_bucket_name" {
  value = aws_s3_bucket.public_bucket.bucket
}

output "open_security_group_id" {
  value = aws_security_group.open_ssh.id
}

output "unencrypted_ebs_id" {
  value = aws_ebs_volume.unencrypted.id
}
