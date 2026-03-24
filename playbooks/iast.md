# IAST Investigation Playbook

## What is IAST?

IAST (Interactive Application Security Testing) finds vulnerabilities in running applications by tracking how user input flows through the code. When a user sends a request, the Datadog tracer instruments the application to follow that input from where it enters (a "source," like a query parameter or form field) to where it's used in a dangerous way (a "sink," like a SQL query or system command). If user input reaches a dangerous sink without proper sanitization, IAST reports it as a vulnerability.

**How it differs from AAP/WAF:** AAP looks at the HTTP request itself and blocks known attack patterns (like `' OR 1=1--`). IAST looks inside the application code to see whether the input actually reaches a dangerous operation. AAP can have false positives (blocking legitimate requests that look suspicious). IAST only fires when the code is genuinely vulnerable.

**How it works in this sandbox:** The 4 pet shop apps are intentionally written with unsanitized code paths. When you send any request (even a normal one like `?q=ball`), IAST traces that input through the code and flags the vulnerability because the code passes it directly into a SQL query without parameterization.

## Quick Start

Select options `1,2` (AAP + IAST) or `7` (All) when running:

```bash
./scripts/up.sh
```

Then send some traffic so IAST can analyze the code paths:

```bash
./scripts/traffic.sh start iast
```

## Verify It's Working

1. Open **Datadog > Security > Application Security > Vulnerabilities**
2. Look for IAST findings on services `petshop-python`, `petshop-node`, etc.
3. Findings should show source-to-sink data flow (e.g., "HTTP parameter `q` flows to SQL query")
4. Check **APM > Traces**, filter by `@iast.enabled:true` to see IAST-tagged spans

## Common Escalation Patterns

### "IAST not finding vulnerabilities"

**What the customer says:** "We enabled IAST but no vulnerabilities show up."

**How to reproduce:**

1. Make sure IAST is enabled (select option 2 during `./scripts/up.sh`, or check that `DD_IAST_ENABLED=true` is in your `.env` file)
2. Send a request that exercises a vulnerable code path:

```bash
curl "http://localhost:8080/py/search?q=test"
```

3. Wait 2-3 minutes, then check **Security > Application Security > Vulnerabilities**
4. If nothing appears, check the app container logs for tracer errors:

```bash
docker compose logs python-app 2>&1 | head -20
```

**What to look for:** Does the tracer version support IAST? Is `DD_IAST_ENABLED` actually reaching the container? Run `docker compose exec python-app env | grep IAST` to confirm.

---

### "IAST performance overhead"

**What the customer says:** "Our app got slower after enabling IAST. How much overhead does it add?"

**What's happening:** IAST instruments string operations and data propagation inside the application. Every time user input is concatenated, split, or passed to a function, the tracer tracks it. This adds CPU overhead proportional to how much data manipulation the app does per request.

**How to test this yourself:**

This sandbox includes a benchmark script and a traffic generator tool called k6 (it runs inside a Docker container, you don't need to install anything). The test sends the same requests at the same rate and measures response times, first with IAST off, then with IAST on.

**Step 1: Run the benchmark with IAST OFF**

```bash
# Make sure DD_IAST_ENABLED=false in .env (it is by default)
grep DD_IAST .env

# Start the apps
./scripts/up.sh    # select option 4 (apps only, no security features)

# Wait ~15 seconds for apps to start, then run the benchmark (60 seconds)
docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml \
  run --rm -e TARGET_HOST=nginx -e TARGET_PORT=80 \
  traffic-normal run /scripts/scenarios/benchmark.js
```

Write down the per-language response times from the output (look for `py_req_duration`, `node_req_duration`, etc.)

**Step 2: Run the benchmark with IAST ON**

```bash
# Enable IAST in .env
sed -i.bak 's/DD_IAST_ENABLED=false/DD_IAST_ENABLED=true/' .env && rm -f .env.bak

# Restart just the app containers so they pick up the new setting
docker compose --profile apps up -d --force-recreate python-app node-app java-app php-app

# Wait ~15 seconds, then run the same benchmark
docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml \
  run --rm -e TARGET_HOST=nginx -e TARGET_PORT=80 \
  traffic-normal run /scripts/scenarios/benchmark.js
```

**Step 3: Compare the numbers**

Typical results from this sandbox (your numbers will vary by machine):

| Language | IAST OFF (avg) | IAST ON (avg) | Overhead |
|----------|---------------|--------------|----------|
| Node     | ~5ms          | ~6ms         | ~11%     |
| Java     | ~6ms          | ~6ms         | ~0%      |
| Python   | ~9ms          | ~9ms         | ~1%      |
| PHP      | ~10ms         | ~10ms        | ~0%      |

At low traffic, IAST overhead is typically 2-5% on average. If a customer reports 20%+ degradation, it's likely something else (misconfigured sampling, excessive span generation, or a tracer bug) rather than IAST taint tracking alone.

**Don't forget to reset:**

```bash
sed -i.bak 's/DD_IAST_ENABLED=true/DD_IAST_ENABLED=false/' .env && rm -f .env.bak
```

---

### "False positive IAST finding"

**What the customer says:** "IAST flagged a SQL injection in our code, but we think it's a false positive."

**How to investigate:**

1. In Datadog, click the IAST finding to see the source-to-sink flow
2. The finding shows exactly which input (e.g., "HTTP parameter `q`") reaches which sink (e.g., "SQL query execution")
3. Check if the code between source and sink sanitizes or parameterizes the input
4. In this sandbox, the vulnerabilities are real (no parameterization), so all findings are true positives

**Key question to ask the customer:** "Is the input parameterized before it reaches the database query?" If they're using an ORM with parameterized queries, it may be a false positive. If they're using string concatenation to build SQL, it's a real vulnerability.

---

### "IAST works in language X but not Y"

**What the customer says:** "IAST detects SQL injection in our Python app but not our Java app."

**How to reproduce:** Send the same request to all 4 apps and compare:

```bash
curl "http://localhost:8080/py/search?q=test"
curl "http://localhost:8080/node/search?q=test"
curl "http://localhost:8080/java/search?q=test"
curl "http://localhost:8080/php/search?q=test"
```

Then check **Security > Application Security > Vulnerabilities** and filter by service.

**What to look for:** Not all tracers support the same set of vulnerability types. Check the [IAST support matrix](https://docs.datadoghq.com/security/application_security/vulnerability_management/iast/) to see which sink types are supported per language and tracer version.

---

### "IAST not detecting deserialization"

**What the customer says:** "We have insecure deserialization but IAST doesn't catch it."

**How to reproduce:**

```bash
curl -X POST http://localhost:8080/py/cart/restore \
  -H "Content-Type: application/json" \
  -d '{"cart_data":"eyJpdGVtcyI6IFsxLCAyXX0="}'
```

**What to look for:** Deserialization detection is newer and not supported in all tracer versions. Check the tracer release notes for when deserialization sink support was added for that language.

## Key Endpoints for IAST Testing

All endpoints work through the nginx gateway at `localhost:8080`. Replace `/py/` with `/node/`, `/java/`, or `/php/` to test other languages.

```bash
# Search: user input goes directly into a SQL query
curl "http://localhost:8080/py/search?q=anything"

# Login: form fields go into a SQL query
curl -X POST "http://localhost:8080/py/login" -d "username=admin&password=test"

# Product: URL path segment goes into a SQL query
curl "http://localhost:8080/py/product/1"

# Upload: filename goes into a file system write
curl -X POST "http://localhost:8080/py/upload" -F "file=@/dev/null" -F "filename=test.txt"

# Webhook: JSON body URL goes into an HTTP request (SSRF)
curl -X POST "http://localhost:8080/py/webhook" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'

# Export: query param goes into a shell command
curl "http://localhost:8080/py/export?file=test.txt"

# Cart restore: body goes into deserialization
curl -X POST "http://localhost:8080/py/cart/restore" \
  -H "Content-Type: application/json" \
  -d '{"cart_data":"eyJpdGVtcyI6IFsxLCAyXX0="}'
```

## Troubleshooting

- **No IAST findings:** Run `docker compose exec python-app env | grep IAST` to confirm `DD_IAST_ENABLED=true` is set. If it's not, check your `.env` file and restart the container.
- **Findings appear for one language but not another:** Check the [IAST support matrix](https://docs.datadoghq.com/security/application_security/vulnerability_management/iast/). Not all sink types are supported in all tracers.
- **High latency with IAST:** See the "IAST performance overhead" section above for how to benchmark it.

## Reference

- [IAST Documentation](https://docs.datadoghq.com/security/application_security/vulnerability_management/iast/)
- [Code Security Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
