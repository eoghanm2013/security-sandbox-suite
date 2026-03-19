# Cloud SIEM Investigation Playbook

## What This Tests

The SIEM event generator produces synthetic logs in the **native format** of real integrations (AWS CloudTrail and Okta). The Datadog Agent collects them with the correct `source` tag, which activates Datadog's built-in log pipelines. The pipelines remap raw fields to standard attributes, and the **OOTB detection rules fire automatically**, producing real Security Signals with zero custom rule configuration.

10 OOTB rules are targeted across two integrations:

| Integration | Rule | Trigger |
|-------------|------|---------|
| CloudTrail | AWS CloudTrail configuration modified | `StopLogging` |
| CloudTrail | AWS GuardDuty detector deleted | `DeleteDetector` |
| CloudTrail | AWS IAM AdministratorAccess policy applied to user | `AttachUserPolicy` |
| CloudTrail | AWS EBS Snapshot Made Public | `ModifySnapshotAttribute` |
| CloudTrail | AWS KMS key deleted or scheduled for deletion | `ScheduleKeyDeletion` |
| CloudTrail | AWS CloudWatch log group deleted | `DeleteLogGroup` |
| Okta | Okta API Token Created or Enabled | `system.api_token.create` |
| Okta | Okta administrator role assigned to user | `user.account.privilege.grant` |
| Okta | Okta MFA reset for user | `user.mfa.factor.reset_all` |
| Okta | Okta policy rule deleted | `policy.rule.delete` |

Some events trigger additional rules too (e.g. `AttachUserPolicy` also fires "AWS IAM policy modified").

## Quick Start

```bash
# Start the base stack
./scripts/up.sh

# Start the SIEM generator (runs on the "siem" profile)
docker compose --profile siem up -d siem-generator

# The generator loops every 60s by default.
# To run once manually:
docker compose exec siem-generator python3 event-generator.py

# Run only CloudTrail or Okta scenarios:
docker compose exec siem-generator python3 event-generator.py --scenario cloudtrail
docker compose exec siem-generator python3 event-generator.py --scenario okta
```

## How It Works

```
event-generator.py
  writes raw CloudTrail JSON  -->  /var/log/sandbox/cloudtrail.log  (source:cloudtrail)
  writes raw Okta System Log  -->  /var/log/sandbox/okta.log        (source:okta)
                                          |
                                   Datadog Agent tails files
                                   (agent/conf.d/siem-logs.yaml)
                                          |
                                   Datadog ingests with source tag
                                          |
                              OOTB log pipeline activates
                              (CloudTrail pipeline, Okta pipeline)
                                          |
                              Fields remapped to standard attributes
                              (eventName -> evt.name, etc.)
                                          |
                              OOTB detection rules match
                                          |
                              Security Signals generated
```

The generator writes logs in the exact same JSON format as the real integrations. The `source` tag on the agent config is what tells Datadog which pipeline to use. No custom rules needed.

## Verify It's Working

1. **Logs:** Open Datadog > **Logs > Search**, filter by `source:cloudtrail` or `source:okta`. You should see events with remapped attributes (`@evt.name`, `@userIdentity.userName`, etc.)

2. **Pipelines:** Go to **Logs > Configuration > Pipelines**. Confirm "AWS CloudTrail" and "Okta" pipelines are enabled.

3. **Signals:** Go to **Security > Cloud SIEM > Signals**. Filter by `env:sandbox`. You should see signals like "AWS CloudTrail configuration modified", "Okta MFA reset for user", etc. Signals may take 2-5 minutes to appear after events are generated.

4. **Quick validation** from the CLI:
```bash
# Check the agent is tailing files
docker compose exec dd-agent agent status | grep -A 5 "siem-logs"

# Check log files exist
docker compose exec siem-generator ls -la /var/log/sandbox/

# Check a sample log
docker compose exec siem-generator head -1 /var/log/sandbox/cloudtrail.log | python3 -m json.tool
```

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "Detection rule not firing" | Generate events, check log ingestion | Verify `source` tag is correct (activates the right pipeline). Check the rule query matches the processed (not raw) attributes. |
| "Logs appear but attributes missing" | Check a log in Log Explorer | If `evt.name` is missing, the pipeline isn't running. Confirm the `source` tag matches the pipeline filter (e.g. `source:cloudtrail`). |
| "Signal created but wrong severity" | Trigger scenario, check signal | Review rule case conditions and severity levels. |
| "Pipeline not remapping fields" | Compare raw vs processed log | The pipeline is read-only (OOTB). If fields aren't remapping, the raw log format might not match what the pipeline expects. Compare your log structure to a real integration event. |

## Troubleshooting

- **No logs in Datadog:** Check the agent is tailing files: `docker compose exec dd-agent agent status | grep -A 10 siem-logs`. Verify the shared volume has files: `docker compose exec siem-generator ls /var/log/sandbox/`.
- **Logs appear but no signals:** Check the `source` tag on your logs. If it says `source:cloudtrail`, the CloudTrail pipeline should activate. If `evt.name` isn't populated, the pipeline isn't processing the logs. Check **Logs > Configuration > Pipelines** to confirm the pipeline is enabled.
- **Signals take a while:** OOTB rules have evaluation windows (typically 300s). First signals may take up to 5 minutes after logs land.
- **Bonus signals:** Some events trigger multiple rules. For example, `ModifySnapshotAttribute` triggers both "EBS Snapshot Made Public" and "EBS Snapshot possible exfiltration". This is expected.

## Reference

- [Cloud SIEM Documentation](https://docs.datadoghq.com/security/cloud_siem/)
- [Detection Rules](https://docs.datadoghq.com/security/cloud_siem/detection_rules/)
- [Log Pipelines](https://docs.datadoghq.com/logs/log_configuration/pipelines/)
- [AWS CloudTrail Integration](https://docs.datadoghq.com/integrations/amazon_cloudtrail/)
- [Okta Integration](https://docs.datadoghq.com/integrations/okta/)
