variable "aws_region" {
  description = "AWS region for sandbox resources"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "sandbox-suite"
}

variable "creator" {
  description = "Creator tag value (firstname.lastname). Required, no default to prevent accidental tagging."
  type        = string
}

variable "team" {
  description = "Team tag value for resource tagging"
  type        = string
  default     = "security-testing"
}
