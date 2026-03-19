# Cloud SIEM Investigation Playbook

## What This Tests

**Local:** The SIEM event generator produces log lines matching common detection rules (brute force, impossible travel, suspicious DNS, privilege escalation). The Datadog Agent forwards these as logs.

**AWS:** CloudTrail, VPC Flow Logs, and GuardDuty provide real cloud-native log sources for SIEM rules to evaluate.

## Quick Start (Local)

```bash
./scripts/up.sh

# Run the event generator (outputs to stdout, agent tails container logs)
docker compose exec python-app python3 /dev/stdin < siem/event-generator.py

# Or run specific scenarios
docker compose exec python-app python3 -c "
import sys; sys.path.insert(0, '/dev/stdin')
" <<< "$(cat siem/event-generator.py)" --scenario brute_force

# For continuous generation, run in a loop
python3 siem/event-generator.py --loop --interval 30 --output /tmp/siem-events.log
```

## Quick Start (AWS)

```bash
# Deploy CloudTrail, VPC Flow Logs, GuardDuty
./scripts/aws-deploy.sh

# Configure Datadog AWS integration to ingest CloudTrail logs
# See: https://docs.datadoghq.com/integrations/amazon_cloudtrail/
```

## Verify It's Working

1. Open Datadog > Security > Cloud SIEM
2. Check Logs > Search for `source:sshd` or `source:auth` (local events)
3. Look for Security Signals triggered by detection rules
4. For AWS: Check CloudTrail logs under `source:cloudtrail`

## Event Scenarios

| Scenario | Detection Rule Pattern | Severity |
|----------|----------------------|----------|
| Brute Force | 15 failed SSH logins + 1 success from same IP | High |
| Impossible Travel | Auth from NYC then Moscow within seconds | Medium |
| Suspicious DNS | Queries to known C2/mining domains | High |
| Privilege Escalation | sudo failures from non-privileged users | High |
| Suspicious Process | base64 decode + exec, reverse shell patterns | Critical |
| Data Exfiltration | Large outbound data transfers to external IPs | High |

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "Detection rule not firing" | Generate matching events, verify log ingestion | Check log pipeline parsing, verify rule query matches log format |
| "Signal created but wrong severity" | Trigger scenario, check signal details | Review rule severity configuration |
| "CloudTrail logs not appearing" | Deploy AWS module, wait for CloudTrail delivery | CloudTrail has ~5min delivery delay, check S3 bucket |
| "Suppression rule not working" | Create suppression, trigger matching event | Verify suppression query matches |

## Troubleshooting

- **No logs in Datadog:** Check agent log collection is enabled, verify `DD_LOGS_ENABLED=true`
- **Logs appear but no signals:** Detection rules may need specific log attributes. Check rule queries.
- **CloudTrail delay:** CloudTrail delivers logs every ~5 minutes. Be patient.

## Reference

- [Cloud SIEM Documentation](https://docs.datadoghq.com/security/cloud_siem/)
- [Detection Rules](https://docs.datadoghq.com/security/cloud_siem/detection_rules/)
- [Cloud SIEM Troubleshooting](https://docs.datadoghq.com/security/cloud_siem/troubleshooting/)
