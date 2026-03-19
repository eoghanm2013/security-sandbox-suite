# IAST Investigation Playbook

## What This Tests

The same 4 vulnerable apps run with `DD_IAST_ENABLED=true`, enabling taint tracking from HTTP input sources to dangerous sinks (SQL queries, file operations, command execution, deserialization). IAST detects exploitable code paths, not just attack payloads.

## Quick Start

```bash
./scripts/up.sh

# Start IAST-specific traffic (sends tainted data through vulnerable code paths)
./scripts/traffic.sh start iast
```

## Verify It's Working

1. Open Datadog > Security > Application Security > Vulnerabilities
2. Look for IAST findings on services `petshop-python`, `petshop-node`, etc.
3. Findings should show source-to-sink data flow (e.g., "HTTP parameter `q` flows to SQL query")
4. Check APM traces for IAST-tagged spans

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "IAST not finding vulnerabilities" | Send tainted input to `/search?q=test` | Verify `DD_IAST_ENABLED=true`, check tracer version supports IAST |
| "IAST performance overhead" | Compare response times with IAST on vs off | Toggle `DD_IAST_ENABLED` and benchmark with k6 |
| "False positive IAST finding" | Check if the detected sink is actually exploitable | Review the source-to-sink flow, check if input is sanitized |
| "IAST works in language X but not Y" | Test same endpoint across all 4 apps | Compare tracer versions, IAST support matrix per language |
| "IAST not detecting deserialization" | POST to `/cart/restore` with tainted data | Check if the tracer version supports deserialization detection |

## Key Endpoints for IAST Testing

```bash
# Source: query param -> Sink: SQL query
curl "http://localhost:8001/search?q=test_iast_input"

# Source: form body -> Sink: SQL query
curl -X POST http://localhost:8001/login -d "username=admin&password=test"

# Source: URL path -> Sink: SQL query (numeric)
curl "http://localhost:8001/product/1"

# Source: form body -> Sink: file system write
curl -X POST http://localhost:8001/upload -F "file=@/dev/null" -F "filename=test.txt"

# Source: JSON body -> Sink: HTTP request (SSRF)
curl -X POST http://localhost:8001/webhook \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'

# Source: query param -> Sink: command execution
curl "http://localhost:8001/export?file=test.txt"

# Source: form body -> Sink: deserialization
curl -X POST http://localhost:8001/cart/restore \
  -H "Content-Type: application/json" \
  -d '{"cart_data":"eyJpdGVtcyI6IFsxLCAyXX0="}'
```

## Troubleshooting

- **No IAST findings:** Ensure `DD_IAST_ENABLED=true` is set. Some tracers require minimum versions for IAST.
- **Findings appear for one language but not another:** Check IAST support matrix. Not all sink types are supported in all tracers.
- **High latency with IAST:** IAST does add overhead. Compare with `DD_IAST_ENABLED=false` to quantify.

## Reference

- [IAST Documentation](https://docs.datadoghq.com/security/application_security/vulnerability_management/iast/)
- [Code Security Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
