# Security Feature Memory Investigation Playbook

## Why This Exists

"We enabled X and memory went up" is a common concern when enabling security products. This playbook covers how to investigate memory impact of Datadog security features.

## Agent-side vs Tracer-side

The critical distinction for security memory investigations:

| Side | Features | Where Memory Impact Is | Container to Monitor |
|------|----------|----------------------|---------------------|
| Agent | CWS, CSPM, VM/SBOM | dd-agent container | `dd-agent` |
| Tracer | AAP, IAST, SCA | App container (via dd-trace) | `python-app`, `node-app`, `java-app`, `php-app` |

A common confusion is reporting "agent memory went up after enabling ASM" when AAP actually runs in the app process, not the agent.

## Monitoring Memory in the Sandbox

Monitor the sandbox suite's agent or app containers while testing:

```bash
# Start sandbox suite
./scripts/up.sh

# Watch agent container memory
docker stats sandbox-suite-dd-agent-1

# Watch all containers
docker stats
```

## Recommended Memory Limits

### Agent-side

| Feature Set | Minimum |
|------------|---------|
| APM + Logs (no security) | 256MB |
| + CWS | 512MB |
| + CWS + CSPM + SBOM | 768MB |
| All agent security | 1GB |

### Tracer-side (app process)

| Feature | Python | Node | Java | PHP |
|---------|--------|------|------|-----|
| AAP | +30-60MB | +40-80MB | +80-150MB | +15-30MB |
| IAST | +40-80MB | +50-100MB | +100-200MB | +20-40MB |
| SCA | +5-15MB | +5-15MB | +10-25MB | +3-10MB |

## Reference

- [Agent Resource Usage](https://docs.datadoghq.com/agent/troubleshooting/agent-resource-usage/)
- [Agent Flare](https://docs.datadoghq.com/agent/troubleshooting/send_a_flare/)
