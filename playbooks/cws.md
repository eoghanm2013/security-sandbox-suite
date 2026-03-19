# CWS (Workload Protection) Investigation Playbook

## What This Tests

The Datadog Agent runs with `DD_RUNTIME_SECURITY_CONFIG_ENABLED=true` and system-probe, monitoring process execution, file access, and network activity inside containers. Trigger scripts generate detectable events.

## Quick Start

```bash
./scripts/up.sh

# Run CWS trigger scripts inside a container
docker compose exec python-app bash -c "apt-get update && apt-get install -y netcat-openbsd && bash /dev/stdin" < cws/trigger-detections.sh

# Or run individual trigger categories
docker compose exec python-app bash -c "$(cat cws/trigger-detections.sh) && trigger_suspicious_process"
```

## Verify It's Working

1. Open Datadog > Security > Workload Security
2. Look for signals from host `sandbox-suite`
3. Check Security > Workload Security > Signals for triggered rules
4. Verify the agent is running system-probe: `docker compose exec dd-agent agent status | grep "Runtime Security"`

## Trigger Categories

| Category | Script | What It Does |
|----------|--------|-------------|
| Suspicious Process | `trigger_suspicious_process` | whoami, uname, ps aux, network recon |
| File Integrity (FIM) | `trigger_fim` | Write to /etc/passwd copy, modify crontab, touch SSH config |
| Crypto-miner Patterns | `trigger_crypto_patterns` | DNS queries to mining pools, miner-named processes |
| Reverse Shell | `trigger_reverse_shell` | nc connection attempts, Python socket connect |
| Metadata Access | `trigger_metadata_access` | curl to AWS/GCP/Azure metadata endpoints |
| Privilege Escalation | `trigger_privesc` | sudo attempts, SUID binary search, capability checks |

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "CWS not detecting process execution" | Run trigger scripts, check signals | Verify system-probe is running, check kernel version |
| "Agent rule not firing" | Check rule expression syntax | Review custom-rules.yaml, verify rule is loaded |
| "FIM not working" | Modify a monitored file, check for signal | Verify FIM paths in agent config |
| "CWS on Fargate/Windows" | Not testable locally (eBPF-less mode) | Escalate with customer environment details |
| "eBPF probe loading failure" | Check `docker compose logs dd-agent` for probe errors | Kernel version must be 4.14+, check security modules |

## Custom Rules

Custom rules are in `cws/custom-rules.yaml`. To load them:

```bash
docker compose cp cws/custom-rules.yaml dd-agent:/etc/datadog-agent/runtime-security.d/
docker compose restart dd-agent
```

## Troubleshooting

- **system-probe not starting:** Ensure `SYS_ADMIN` capability is granted, check Docker socket mount
- **No signals:** Verify `DD_RUNTIME_SECURITY_CONFIG_ENABLED=true`, check agent status
- **Kernel compatibility:** CWS requires kernel 4.14+ with eBPF support. macOS Docker Desktop uses a Linux VM, so this should work.

## Reference

- [CWS Documentation](https://docs.datadoghq.com/security/cloud_workload_security/)
- [Custom Rules Guide](https://docs.datadoghq.com/security/cloud_workload_security/agent_expressions/)
- [CWS Troubleshooting](https://docs.datadoghq.com/security/cloud_workload_security/troubleshooting/)
