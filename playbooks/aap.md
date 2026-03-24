# AAP (App & API Protection) Investigation Playbook

## What is AAP?

AAP (App & API Protection, formerly called ASM/AppSec) adds a Web Application Firewall (WAF) inside your application. Instead of sitting in front of your app like a traditional network WAF, it runs inside the Datadog tracing library. This means it can see the full HTTP request in the context of your application code and block known attack patterns like SQL injection, XSS, and command injection.

**How it works in this sandbox:** The 4 pet shop apps run with `DD_APPSEC_ENABLED=true`. The traffic generators send both normal requests and attack payloads. The in-app WAF detects the attack patterns and reports them as security traces to Datadog, where they show up as attack attempts in the Application Security section.

## Quick Start

Select option `1` (AAP) or `7` (All) when running:

```bash
./scripts/up.sh
```

Then start attack traffic:

```bash
./scripts/traffic.sh start attacks
```

## Verify It's Working

1. Open **Datadog > Security > Application Security**
2. You should see services: `petshop-python`, `petshop-node`, `petshop-java`, `petshop-php`
3. Attack attempts should appear within 2-3 minutes of starting traffic
4. Check **APM > Traces**, filter by `@appsec.event:true` to see security traces

## Common Escalation Patterns

### "WAF not detecting attacks"

**What the customer says:** "We're sending SQL injection payloads but nothing shows up in Application Security."

**How to reproduce:**

1. Start the sandbox with AAP enabled (option 1 during `./scripts/up.sh`)
2. Send a SQL injection attack:

```bash
curl "http://localhost:8080/py/search?q=%27%20OR%20%271%27%3D%271"
```

3. Wait 2-3 minutes, then check **Security > Application Security > Signals**
4. If nothing appears, verify the setting reached the container:

```bash
docker compose exec python-app env | grep APPSEC
```

**What to look for:** Is `DD_APPSEC_ENABLED=true` set? Is the tracer version recent enough to support AAP? Check `docker compose logs python-app` for tracer initialization errors.

---

### "False positive on WAF rule"

**What the customer says:** "The WAF is flagging legitimate user searches as SQL injection."

**How to investigate:**

1. Send a normal (non-malicious) search query and see if it gets flagged:

```bash
curl "http://localhost:8080/py/search?q=dog food"
```

2. Then send an actual attack:

```bash
curl "http://localhost:8080/py/search?q=%27%20OR%201%3D1--"
```

3. Compare the two in **APM > Traces** (filter by `@appsec.event:true`). The normal query should not appear, only the attack.
4. If the normal query is flagged, click the trace to see which WAF rule fired and its ID. That rule may need tuning.

---

### "Attacks not in traces"

**What the customer says:** "We see normal APM traces but no security events in them."

**How to reproduce:**

```bash
# Send an attack through the nginx gateway (this is the normal path)
curl "http://localhost:8080/py/search?q=%27%20OR%201%3D1--"

# Also try hitting the app directly (bypassing nginx)
curl "http://localhost:8001/search?q=%27%20OR%201%3D1--"
```

**What to look for:** If attacks show up when hitting the app directly but not through nginx, it could be a proxy stripping headers. If they don't show up either way, check that the agent is reachable from the app container: `docker compose exec python-app curl -s http://dd-agent:8126/info`

## Manual Attack Testing

All endpoints work through the nginx gateway. Replace `/py/` with `/node/`, `/java/`, or `/php/` to test other languages.

```bash
# SQL Injection (should trigger WAF)
curl "http://localhost:8080/py/search?q=%27%20OR%20%271%27%3D%271"

# XSS (should trigger WAF)
curl "http://localhost:8080/py/profile/%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Command Injection
curl "http://localhost:8080/py/export?file=%3Bcat%20%2Fetc%2Fpasswd"

# SSRF (request to cloud metadata endpoint)
curl -X POST "http://localhost:8080/py/webhook" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

## Troubleshooting

- **No security traces:** Check the agent is running with `docker compose ps dd-agent`. Is it healthy?
- **Attacks not detected:** Run `docker compose exec python-app env | grep APPSEC` to confirm the flag is set. Restart the container if you changed `.env` after it started.
- **Partial detection:** Some attack types may not be covered by the default WAF rule set. Check the trace details for the rule set version.
- **PHP issues:** Check `docker compose logs php-app` for dd-trace-php extension loading errors.

## Reference

- [Datadog ASM Documentation](https://docs.datadoghq.com/security/application_security/)
- [WAF Rules Reference](https://docs.datadoghq.com/security/application_security/threats/inapp_waf_rules/)
- [ASM Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
