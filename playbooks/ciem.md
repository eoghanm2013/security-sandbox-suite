# CIEM (Identity Risk Management) Investigation Playbook

## What This Tests

The Terraform module creates IAM resources with intentional identity risks: overly permissive policies, cross-account access, stale access keys, and admin users without MFA. Datadog CIEM analyzes these to identify privilege escalation paths and excessive permissions.

## Quick Start

```bash
./scripts/aws-deploy.sh
```

CIEM findings appear after Datadog processes the IAM configuration (typically within the cloud scan cycle).

## Deployed Identity Risks

| Resource | Risk | Expected CIEM Finding |
|----------|------|----------------------|
| IAM User `sandbox-suite-admin-no-mfa` | AdminAccess, no MFA | "IAM user with admin access has no MFA" |
| IAM Role `sandbox-suite-cross-account-role` | AssumeRole by any AWS account (`*`) | "IAM role allows cross-account access from any principal" |
| IAM Role `sandbox-suite-cross-account-role` | Full `*:*` permissions | "IAM role has unrestricted permissions" |
| IAM User `sandbox-suite-stale-key` | Access key with broad permissions | "IAM user has overly permissive policy" |
| IAM Role `sandbox-suite-unused-perms` | Lambda role with AdministratorAccess | "Service role has excessive permissions" |

## Verify It's Working

1. Open Datadog > Security > Identity Risks
2. Filter by tag `service:security-sandbox-suite`
3. Look for identity risk findings showing privilege escalation paths
4. Check the blast radius analysis for over-permissioned roles

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "CIEM not detecting overly permissive role" | Deploy module, wait for scan | Check AWS integration, verify IAM permissions for Datadog |
| "Identity risk score seems wrong" | Review the specific role's permissions | Check unused permission analysis, blast radius |
| "Cross-account access not detected" | Review the trust policy on the role | Verify Datadog has access to STS/IAM APIs |
| "Stale access key not flagged" | Check key age and last used date | CIEM tracks key age and activity patterns |

## Cleanup

```bash
./scripts/aws-destroy.sh
```

## Troubleshooting

- **No identity findings:** Verify AWS integration includes IAM access, check Datadog CIEM is enabled
- **Partial findings:** Some findings require cross-service analysis. Ensure the integration covers IAM, STS, and Organizations.
- **Delayed findings:** CIEM runs on the cloud scan cycle, typically every few hours

## Reference

- [CIEM Documentation](https://docs.datadoghq.com/security/cloud_security_management/identity_risks/)
- [CIEM Documentation](https://docs.datadoghq.com/security/cloud_security_management/identity_risks/)
