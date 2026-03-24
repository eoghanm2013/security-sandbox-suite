# Cloud SIEM Investigation Playbook

## What is Cloud SIEM?

Cloud SIEM (Security Information and Event Management) applies detection rules to logs as they're ingested into Datadog. When a log matches a rule's conditions (e.g., "5 failed logins from the same IP in 10 minutes"), it creates a Security Signal. Think of it as automated alert rules that watch your logs 24/7 for suspicious patterns.

Datadog ships hundreds of out-of-the-box (OOTB) detection rules for common log sources like AWS CloudTrail, Okta, GitHub, and more. You don't need to write rules yourself for standard integrations.

**How it works in this sandbox:** A Python script generates fake but realistic log events in the exact JSON format of AWS CloudTrail and Okta System Logs. The Datadog Agent reads these log files and sends them to Datadog with the correct `source` tag (`cloudtrail` or `okta`). This activates Datadog's built-in log pipelines, which parse the JSON and extract the right attributes. The OOTB detection rules then fire automatically, generating real Security Signals with zero manual rule setup.

## Quick Start

Select option `6` (SIEM) or `7` (All) when running:

```bash
./scripts/up.sh
```

Or start the SIEM generator manually alongside an existing stack:

```bash
docker compose --profile siem up -d siem-generator
```

## What Gets Generated

The event generator produces 10 events (6 CloudTrail + 4 Okta) that target these OOTB detection rules:

| Integration | Event | OOTB Rule It Triggers |
|-------------|-------|-----------------------|
| CloudTrail | `StopLogging` on a trail | AWS CloudTrail configuration modified |
| CloudTrail | `DeleteDetector` (GuardDuty) | AWS GuardDuty detector deleted |
| CloudTrail | `AttachUserPolicy` with AdministratorAccess | AWS IAM AdministratorAccess policy applied |
| CloudTrail | `ModifySnapshotAttribute` (public EBS) | AWS EBS Snapshot Made Public |
| CloudTrail | `ScheduleKeyDeletion` (KMS) | AWS KMS key scheduled for deletion |
| CloudTrail | `DeleteLogGroup` (CloudWatch) | AWS CloudWatch log group deleted |
| Okta | `system.api_token.create` | Okta API Token Created or Enabled |
| Okta | Admin role assigned to user | Okta administrator role assigned |
| Okta | All MFA factors reset | Okta MFA reset for user |
| Okta | Policy rule deleted | Okta policy rule deleted |

Some events trigger additional rules too (e.g., `AttachUserPolicy` also fires "AWS IAM policy modified"), so you may see more than 10 signals.

Events run once on startup, then repeat every 5 minutes.

## Verify It's Working

1. Check the agent is reading the log files:

```bash
docker compose exec dd-agent agent status 2>&1 | grep -A 10 "siem-logs"
```

You should see `cloudtrail.log` and `okta.log` with `Status: OK`.

2. Open **Datadog > Logs > Search** and filter by `source:cloudtrail` or `source:okta`
3. Verify the logs appear with properly parsed attributes (click a log to inspect)
4. Open **Datadog > Security > Cloud SIEM > Signals** and filter by `env:sandbox`
5. Signals should appear within 2-5 minutes

## Common Escalation Patterns

### "Detection rule not firing"

**What the customer says:** "We're ingesting CloudTrail logs but the detection rule isn't creating signals."

**How to investigate:**

1. Open **Logs > Search** and find the relevant logs
2. Click a log and check the `source` tag. It must match what the detection rule expects (e.g., `cloudtrail`, not `aws` or `custom`)
3. Check that the OOTB log pipeline is processing the logs: the parsed attributes should appear as facets (e.g., `@evt.name`, `@userIdentity.arn`)
4. Open the detection rule and look at its query. Copy the query into Log Search and see if your logs match

**In this sandbox:** If logs appear but signals don't, the most common cause is the `source` tag being wrong. Check `agent/conf.d/siem-logs.yaml` to see what source tags are configured.

---

### "Logs appear but attributes are missing"

**What the customer says:** "The logs show up in Log Explorer but the attributes the rule needs aren't there."

**What's happening:** Datadog uses log pipelines to parse raw logs into structured attributes. The pipeline is activated by the `source` tag. If the source is `cloudtrail`, Datadog applies the CloudTrail pipeline and extracts fields like `@userIdentity.arn`, `@eventName`, etc.

**How to check:**
1. Open **Logs > Configuration > Pipelines**
2. Find the pipeline for the relevant source (e.g., "CloudTrail")
3. Make sure it's enabled
4. Click a log in Log Search and check if the extracted attributes match what the detection rule queries

---

### "CloudTrail logs not appearing (AWS)"

**What the customer says:** "We set up the AWS integration but no CloudTrail logs show up."

**Note:** This requires the AWS module (not testable with just the local stack). CloudTrail delivers logs to S3 every ~5 minutes, and then the Datadog AWS integration reads them from S3. There's a delay of 5-15 minutes before logs appear.

## Quick Start (AWS)

```bash
./scripts/aws-deploy.sh    # Deploys CloudTrail, VPC Flow Logs, GuardDuty via Terraform
./scripts/aws-destroy.sh   # Tear down when done
```

Configure the Datadog AWS integration to ingest CloudTrail logs. See: [CloudTrail Integration Docs](https://docs.datadoghq.com/integrations/amazon_cloudtrail/)

## Troubleshooting

- **No logs in Datadog:** Run `docker compose exec dd-agent agent status 2>&1 | grep -A 10 "siem-logs"` to check the agent is tailing the files. Verify log files exist: `docker compose exec siem-generator ls -la /var/log/sandbox/`
- **Logs appear but no signals:** Check the `source` tag on your logs in Log Explorer. If it's wrong (e.g., `source:file` instead of `source:cloudtrail`), the OOTB rules won't match.
- **Generator not producing events:** Check its logs: `docker compose logs siem-generator --tail 20`

## Reference

- [Cloud SIEM Documentation](https://docs.datadoghq.com/security/cloud_siem/)
- [Detection Rules](https://docs.datadoghq.com/security/cloud_siem/detection_rules/)
- [CloudTrail Integration](https://docs.datadoghq.com/integrations/amazon_cloudtrail/)
- [Okta Integration](https://docs.datadoghq.com/integrations/okta/)
