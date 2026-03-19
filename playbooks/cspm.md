# CSPM (Cloud Security Misconfigurations) Investigation Playbook

## What This Tests

The Terraform AWS module creates intentionally misconfigured resources that Datadog CSPM should detect. This provides a known-good baseline for comparing against customer CSPM findings.

## Quick Start

```bash
# Deploy misconfigured resources to AWS
./scripts/aws-deploy.sh
```

After deployment, Datadog's cloud integration scans resources agentlessly. Findings typically appear within 1-12 hours depending on the scan cycle.

## Deployed Misconfigurations

| Resource | Misconfiguration | Expected CSPM Finding |
|----------|-----------------|----------------------|
| S3 bucket `sandbox-suite-public-misconfig` | Public read access via bucket policy | "S3 bucket is publicly accessible" |
| S3 bucket `sandbox-suite-no-versioning` | Versioning disabled | "S3 bucket versioning is not enabled" |
| S3 bucket `sandbox-suite-no-encryption` | No server-side encryption | "S3 bucket default encryption is not enabled" |
| Security Group `sandbox-suite-open-ssh` | SSH (22) open to 0.0.0.0/0 | "Security group allows ingress from 0.0.0.0/0 to port 22" |
| Security Group `sandbox-suite-open-ssh` | All TCP ports open to 0.0.0.0/0 | "Security group allows unrestricted ingress" |
| EBS Volume `sandbox-suite-unencrypted-ebs` | Encryption disabled | "EBS volume is not encrypted" |

## Verify It's Working

1. Open Datadog > Security > Cloud Security > Misconfigurations
2. Filter by tag `service:security-sandbox-suite`
3. You should see findings for each misconfigured resource
4. Each finding maps to a CIS benchmark or compliance framework rule

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "CSPM not detecting misconfigured resource" | Deploy the module, wait for scan cycle | Check cloud integration is configured, verify resource tags |
| "Finding doesn't match compliance framework" | Review the specific CIS/PCI-DSS rule mapping | Check which frameworks are enabled in Datadog |
| "Finding persists after remediation" | Fix the resource, wait for next scan | CSPM scans every ~12 hours. Force rescan if available. |
| "Muted finding reappearing" | Mute a finding, wait for scan cycle | Check mute scope (resource-specific vs rule-wide) |

## Cleanup

```bash
./scripts/aws-destroy.sh
```

**Important:** Cloud Security auto-remediation may fix some of these misconfigurations automatically. If findings disappear unexpectedly, check the auto-remediation logs.

## Troubleshooting

- **No findings:** Verify AWS integration is configured in Datadog, check the correct AWS account is connected
- **Delayed findings:** CSPM scans are agentless and run on a cycle (up to 12 hours). Be patient.
- **Wrong account:** Ensure the correct AWS account is integrated with your Datadog org

## Reference

- [CSPM Documentation](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/)
- [CIS Benchmarks](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/frameworks_and_benchmarks/)
- [Cloud Security FAQ](https://docs.datadoghq.com/security/cloud_security_management/troubleshooting/)
