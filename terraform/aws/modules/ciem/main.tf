variable "name_prefix" {
  type = string
}

data "aws_caller_identity" "current" {}

# --- CIEM Finding: IAM User with Admin Access and No MFA ---

resource "aws_iam_user" "admin_no_mfa" {
  name          = "${var.name_prefix}-admin-no-mfa"
  force_destroy = true
  tags          = { ciem = "true", risk = "high" }
}

resource "aws_iam_user_policy_attachment" "admin_no_mfa" {
  user       = aws_iam_user.admin_no_mfa.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- CIEM Finding: IAM User with Stale Access Key ---

resource "aws_iam_user" "stale_key_user" {
  name          = "${var.name_prefix}-stale-key"
  force_destroy = true
  tags          = { ciem = "true", risk = "medium" }
}

resource "aws_iam_access_key" "stale_key" {
  user = aws_iam_user.stale_key_user.name
}

resource "aws_iam_user_policy" "stale_key_policy" {
  name = "${var.name_prefix}-stale-key-policy"
  user = aws_iam_user.stale_key_user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:*", "iam:*"]
      Resource = "*"
    }]
  })
}

# --- CIEM Finding: Overly Permissive Cross-Account Role ---

resource "aws_iam_role" "cross_account" {
  name = "${var.name_prefix}-cross-account-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { ciem = "true", risk = "critical" }
}

resource "aws_iam_role_policy" "cross_account_policy" {
  name = "${var.name_prefix}-cross-account-policy"
  role = aws_iam_role.cross_account.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# --- CIEM Finding: Service Role with Unused Permissions ---

resource "aws_iam_role" "unused_perms" {
  name = "${var.name_prefix}-unused-perms"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { ciem = "true", risk = "medium" }
}

resource "aws_iam_role_policy_attachment" "unused_perms" {
  role       = aws_iam_role.unused_perms.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "no_mfa_user_name" {
  value = aws_iam_user.admin_no_mfa.name
}

output "cross_account_role_arn" {
  value = aws_iam_role.cross_account.arn
}
