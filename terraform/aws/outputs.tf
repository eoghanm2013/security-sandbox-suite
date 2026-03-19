output "cspm_findings" {
  description = "Resources that should generate CSPM findings"
  value = {
    public_bucket     = module.cspm.public_bucket_name
    open_sg           = module.cspm.open_security_group_id
    no_mfa_user       = module.ciem.no_mfa_user_name
    unencrypted_ebs   = module.cspm.unencrypted_ebs_id
  }
}

output "vm_targets" {
  description = "VM scanning targets"
  value = {
    vulnerable_instance_id = module.vm.instance_id
    vulnerable_ecr_repo    = module.vm.ecr_repo_url
  }
}

output "siem_sources" {
  description = "Cloud SIEM log sources"
  value = {
    cloudtrail_bucket = module.siem.cloudtrail_bucket
    guardduty_id      = module.siem.guardduty_detector_id
  }
}
