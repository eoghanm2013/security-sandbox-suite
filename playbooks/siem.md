# Cloud SIEM Investigation Playbook

## What This Tests

**Local:** The SIEM event generator writes log files that the Datadog Agent tails with correct `source` tags (sshd, auth, dns, sudo, auditd, firewall). Each scenario produces logs with Datadog standard attributes (`evt.name`, `evt.category`, `evt.outcome`, `usr.id`, `network.client.ip`) so they match OOTB detection rules.

**AWS:** CloudTrail, VPC Flow Logs, and GuardDuty provide real cloud-native log sources for SIEM rules to evaluate.

## Quick Start (Local)

```bash
# Start the stack with the SIEM generator
./scripts/up.sh
docker compose --profile siem up -d siem-generator

# Or run a single scenario manually
docker compose exec siem-generator python3 event-generator.py --scenario brute_force

# Run all scenarios once (no loop)
docker compose exec siem-generator python3 event-generator.py --loop false
```

The generator writes to `/var/log/sandbox/` inside a shared volume. The agent tails these files with per-source configs:

| Log file | Agent `source` tag | Scenarios |
|----------|-------------------|-----------|
| `sshd.log` | `sshd` | Brute force SSH |
| `auth.log` | `auth` | Impossible travel |
| `dns.log` | `dns` | Suspicious DNS queries |
| `sudo.log` | `sudo` | Privilege escalation |
| `auditd.log` | `auditd` | Suspicious process execution |
| `firewall.log` | `firewall` | Data exfiltration |

## Quick Start (AWS)

```bash
# Deploy CloudTrail, VPC Flow Logs, GuardDuty
./scripts/aws-deploy.sh

# Configure Datadog AWS integration to ingest CloudTrail logs
# See: https://docs.datadoghq.com/integrations/amazon_cloudtrail/
```

## Verify It's Working

1. Open Datadog > **Logs > Search**
2. Filter by `source:sshd` or `source:auth` or `source:dns`
3. Verify logs appear with the correct standard attributes (`@evt.outcome`, `@usr.id`, `@network.client.ip`)
4. Go to **Security > Cloud SIEM** and look for Security Signals
5. For AWS: Check CloudTrail logs under `source:cloudtrail`

## Event Scenarios

| Scenario | What it generates | Key attributes for rules |
|----------|------------------|------------------------|
| Brute Force | 15 failed SSH logins + 1 success from same IP | `@evt.outcome:failure`, `@network.client.ip`, `@usr.id` |
| Impossible Travel | Auth from NYC then Moscow within seconds | `@evt.outcome:success`, `@network.client.geoip`, `@usr.id` |
| Suspicious DNS | Queries to known C2/mining domains | `@dns.question.name` |
| Privilege Escalation | sudo failures from non-privileged users | `@evt.outcome:failure`, `@usr.id` |
| Suspicious Process | base64 decode + exec, reverse shell patterns | `@process.command_line`, `@usr.id` |
| Data Exfiltration | Large outbound data transfers to external IPs | `@network.destination.ip`, `@network.bytes_written` |

## How It Works

The event generator uses Datadog's [standard log attributes](https://docs.datadoghq.com/logs/log_configuration/attributes_naming_convention/):

- `evt.name`, `evt.category`, `evt.outcome` for event classification
- `usr.id` for user identification
- `network.client.ip` / `network.client.geoip` for source IPs and geo
- `dns.question.name` for DNS queries
- `process.command_line` for process execution
- `status` (reserved attribute) for log severity

The agent config at `agent/conf.d/siem-logs.yaml` maps each log file to the correct `source` tag, which activates Datadog's OOTB log pipelines and ensures detection rules can filter by source.

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "Detection rule not firing" | Generate matching events, verify log ingestion | Check `source` tag is correct, verify rule query matches log attributes |
| "Signal created but wrong severity" | Trigger scenario, check signal details | Review rule severity configuration |
| "Logs appear but attributes missing" | Check log in Log Explorer | Verify pipeline is applied (correct `source` tag activates OOTB pipelines) |
| "CloudTrail logs not appearing" | Deploy AWS module, wait for CloudTrail delivery | CloudTrail has ~5min delivery delay, check S3 bucket |

## Troubleshooting

- **No logs in Datadog:** Run `docker compose logs dd-agent | grep siem` to check the agent is tailing the files. Verify the shared volume has log files with `docker compose exec siem-generator ls -la /var/log/sandbox/`.
- **Logs appear but no signals:** Check the `source` tag on your logs in Log Explorer. If it's wrong, the OOTB rules won't match. The agent config at `agent/conf.d/siem-logs.yaml` controls this.
- **Wrong attributes:** Make sure the OOTB pipeline for the source (e.g., `sshd`) is enabled in Log Configuration > Pipelines. The pipeline remaps JSON attributes to standard facets.
- **CloudTrail delay:** CloudTrail delivers logs every ~5 minutes. Be patient.

## Reference

- [Cloud SIEM Documentation](https://docs.datadoghq.com/security/cloud_siem/)
- [Detection Rules](https://docs.datadoghq.com/security/cloud_siem/detection_rules/)
- [Standard Log Attributes](https://docs.datadoghq.com/logs/log_configuration/attributes_naming_convention/)
- [Monitor Authentication Logs for Security Threats](https://docs.datadoghq.com/security/cloud_siem/guide/monitor-authentication-logs-for-security-threats/)
