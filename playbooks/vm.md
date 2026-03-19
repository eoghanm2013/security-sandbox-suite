# VM (Vulnerability Management) Investigation Playbook

## What This Tests

The Terraform module creates an EC2 instance running Ubuntu 20.04 with pinned vulnerable packages, plus an ECR repository for vulnerable container images. Datadog's vulnerability scanner (agent-based and agentless) should detect CVEs on both.

## Quick Start

```bash
./scripts/aws-deploy.sh

# After deployment, install the Datadog Agent on the EC2 instance
# for agent-based vulnerability scanning.
# The instance is also a target for agentless scanning.
```

## Deployed Vulnerable Targets

| Target | Vulnerable Packages | Expected Findings |
|--------|-------------------|-------------------|
| EC2 `sandbox-suite-vulnerable-host` (Ubuntu 20.04) | openssl 1.1.1, curl 7.68, sudo, imagemagick, ghostscript | Multiple CVEs including openssh, libxml2 |
| ECR `sandbox-suite-vulnerable-images` | (Push vulnerable base images here) | Image layer CVEs |

## Verify It's Working

1. Open Datadog > Security > Infrastructure Vulnerabilities
2. Filter by host tag `service:security-sandbox-suite`
3. Verify CVE findings with severity scores (CVSS + EPSS + CISA KEV)
4. For container images: Push a vulnerable image to the ECR repo, check Image Vulnerabilities

## Pushing a Vulnerable Image to ECR

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account_id>.dkr.ecr.us-east-1.amazonaws.com

# Tag and push a known-vulnerable base image
docker pull ubuntu:20.04
docker tag ubuntu:20.04 <ecr_repo_url>:vulnerable-base
docker push <ecr_repo_url>:vulnerable-base
```

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "VM not detecting CVEs on host" | Check agent is running with SBOM enabled | Verify `sbom.enabled` and `sbom.host.enabled` in agent config |
| "Agentless scan not finding vulnerabilities" | Wait for scan cycle (up to 12h) | Check agentless scanning is configured for the AWS account |
| "Severity doesn't match NVD" | Check CVE detail in Datadog | Datadog enriches with EPSS, CISA KEV, and runtime context |
| "Container image vulns missing" | Push image to ECR, wait for scan | Verify ECR integration and scan-on-push |
| "Agent-based vs agentless results differ" | Compare findings from both | Agent-based sees running packages, agentless sees installed packages |

## Cleanup

```bash
./scripts/aws-destroy.sh
```

## Troubleshooting

- **No host vulnerabilities:** Verify SBOM collection is enabled in agent config, check agent version
- **ECR images not scanned:** Verify ECR integration, check scan-on-push is enabled
- **Delayed findings:** Agentless scanning runs on a cycle. Agent-based is faster but requires agent on the host.

## Reference

- [Vulnerability Management Documentation](https://docs.datadoghq.com/security/cloud_security_management/vulnerabilities/)
- [SBOM Collection](https://docs.datadoghq.com/security/cloud_security_management/vulnerabilities/setup/)
- [VM Troubleshooting](https://docs.datadoghq.com/security/cloud_security_management/vulnerabilities/)
