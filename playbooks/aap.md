# AAP (App & API Protection) Investigation Playbook

## What This Tests

The sandbox runs 4 vulnerable web apps (Python, Node, Java, PHP) with `DD_APPSEC_ENABLED=true`. Each app has identical attack surfaces, letting you compare WAF detection across tracers and reproduce customer-reported AppSec issues.

Products covered: In-App WAF, IP blocking, user blocking, attack attempt detection, security traces.

## Quick Start

```bash
# Start the full stack
./scripts/up.sh

# Verify apps are running
curl http://localhost:8080/py/health
curl http://localhost:8080/node/health
curl http://localhost:8080/java/health
curl http://localhost:8080/php/health

# Start attack traffic to generate AAP signals
./scripts/traffic.sh start attacks
```

## Verify It's Working

1. Open Datadog > Security > Application Security
2. You should see services: `petshop-python`, `petshop-node`, `petshop-java`, `petshop-php`
3. Attack attempts should appear within 2-3 minutes of starting traffic
4. Check APM > Traces, filter by `@appsec.event:true` to see security traces

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "WAF not detecting attacks" | Send SQLi to `/search?q=' OR 1=1--` | Check `DD_APPSEC_ENABLED=true` in env, verify traces have appsec tags |
| "False positive on WAF rule" | Send normal search query, check if flagged | Review the specific rule ID, check WAF rule configuration |
| "IP blocking not working" | Use Datadog API to block an IP, then send requests from it | Verify `DD_APPSEC_ENABLED=true`, check tracer version supports blocking |
| "Attacks not in traces" | Send attacks directly to app port (e.g., :8001) | Verify agent connectivity, check `DD_TRACE_AGENT_PORT` |
| "Tracer version X behaves differently" | Change tracer version in Dockerfile, rebuild | Compare attack detection between versions |

## Manual Attack Testing

```bash
# SQL Injection (should trigger WAF)
curl "http://localhost:8001/search?q=' OR '1'='1"

# XSS (should trigger WAF)
curl "http://localhost:8001/profile/<script>alert(1)</script>"

# Command Injection
curl "http://localhost:8001/export?file=;cat /etc/passwd"

# SSRF
curl -X POST http://localhost:8001/webhook \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

## Troubleshooting

- **No security traces:** Check agent is running (`docker compose ps dd-agent`), verify `DD_APM_ENABLED=true`
- **Attacks not detected:** Confirm `DD_APPSEC_ENABLED=true` is set, restart app container
- **Partial detection:** Some attack types may not be covered by default rules. Check the WAF rule set version.
- **PHP helper/sidecar issues:** Check `docker compose logs php-app` for dd-trace-php extension loading errors

## Reference

- [Datadog ASM Documentation](https://docs.datadoghq.com/security/application_security/)
- [WAF Rules Reference](https://docs.datadoghq.com/security/application_security/threats/inapp_waf_rules/)
- [ASM Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
