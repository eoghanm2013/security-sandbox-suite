# SCA (Software Composition Analysis) Investigation Playbook

## What is SCA?

SCA (Software Composition Analysis) checks the third-party libraries your application uses for known security vulnerabilities (CVEs). Most modern apps are 80%+ open-source code, so a vulnerability in a dependency like Log4j or Jinja2 can be just as dangerous as a bug in your own code.

**Two modes:**
- **Runtime SCA** (`DD_APPSEC_SCA_ENABLED=true`): The tracer detects which libraries are actually loaded when the app runs, and reports any with known CVEs. This only flags libraries that are genuinely in use.
- **Static SCA**: Scans dependency manifests (`requirements.txt`, `package.json`, `pom.xml`) in your repo or CI pipeline. This catches everything declared, even dev-only dependencies that never run in production.

**How it works in this sandbox:** Each app intentionally pins old, vulnerable versions of popular libraries. When the apps start with SCA enabled, the tracer reports these to Datadog, and they appear as library vulnerabilities in the Security section.

### Pinned Vulnerable Dependencies

| Language | Package | Version | Known CVEs |
|----------|---------|---------|-----------|
| Python | pyyaml | 5.3.1 | CVE-2020-14343 (arbitrary code execution) |
| Python | Jinja2 | 3.1.2 | CVE-2024-22195 (XSS) |
| Python | requests | 2.25.0 | CVE-2023-32681 (header leak) |
| Python | Pillow | 9.5.0 | Multiple CVEs |
| Node | lodash | 4.17.20 | CVE-2021-23337 (command injection) |
| Node | jsonwebtoken | 8.5.1 | CVE-2022-23529 (insecure key handling) |
| Node | express | 4.17.1 | CVE-2024-29041 (open redirect) |
| Node | ejs | 3.1.6 | CVE-2022-29078 (RCE) |
| Java | log4j-core | 2.14.1 | CVE-2021-44228 (Log4Shell) |
| Java | jackson-databind | 2.15.0 | Multiple CVEs |
| PHP | guzzlehttp/guzzle | 7.4.0 | CVE-2022-29248 (cookie handling) |
| PHP | symfony/http-kernel | 6.2.0 | Multiple CVEs |

## Quick Start

Select option `3` (SCA) or `7` (All) when running:

```bash
./scripts/up.sh
```

SCA runs automatically when the apps start. You just need to send some traffic so the tracer reports the loaded libraries:

```bash
./scripts/traffic.sh start normal
```

## Verify It's Working

1. Open **Datadog > Security > Application Security > Vulnerabilities**
2. Filter by vulnerability type: "Library Vulnerability"
3. You should see findings for each service's vulnerable dependencies
4. Click a finding to see the affected library, CVE, and severity score

## Common Escalation Patterns

### "SCA not detecting vulnerable library"

**What the customer says:** "We have Log4j 2.14.1 in our Java app but SCA doesn't report it."

**How to investigate:**

1. Confirm SCA is enabled:

```bash
docker compose exec java-app env | grep SCA
# Should show DD_APPSEC_SCA_ENABLED=true
```

2. Send a few requests so the tracer has a chance to report loaded libraries:

```bash
curl "http://localhost:8080/java/health"
curl "http://localhost:8080/java/search?q=test"
```

3. Wait 2-3 minutes, then check **Security > Application Security > Vulnerabilities**
4. If still nothing, check tracer logs for errors: `docker compose logs java-app 2>&1 | head -30`

**Key distinction:** Runtime SCA only reports libraries that are actually loaded into memory. If a library is in `pom.xml` but never imported by the code, runtime SCA won't see it. Static SCA (in CI) catches those.

---

### "SCA shows dev-only deps as runtime"

**What the customer says:** "SCA flagged a library that's only in our dev dependencies, not production."

**How to explain:** If they're seeing it in runtime SCA, the library is being loaded at runtime regardless of where it's declared. This can happen if a test framework or dev tool is accidentally bundled into the production image. If they're seeing it in static SCA only, that's expected since static scans read the manifest file and can't distinguish dev vs production dependencies without explicit configuration.

---

### "Severity doesn't match NVD"

**What the customer says:** "NVD says this CVE is a 9.8 Critical but Datadog shows it as High."

**How to explain:** Datadog doesn't use raw CVSS scores alone. The severity factors in:
- **CVSS base score** (from NVD)
- **EPSS** (Exploit Prediction Scoring System, likelihood of real-world exploitation)
- **CISA KEV** (Known Exploited Vulnerabilities catalog)
- **Runtime context** (is the vulnerable function actually reachable?)

This means a CVE with a high CVSS but no known exploits and no reachable code path may be scored lower than one with a moderate CVSS that's actively exploited.

## Troubleshooting

- **No SCA findings:** Run `docker compose exec python-app env | grep SCA` to confirm the flag is set. Send some traffic so the tracer reports loaded libraries.
- **Partial findings:** Not all package ecosystems have the same CVE coverage. Java and Python have the broadest coverage.
- **Runtime vs static mismatch:** Runtime SCA only reports libraries actually loaded at runtime. Static SCA reads manifests. The two will differ.

## Reference

- [SCA Documentation](https://docs.datadoghq.com/security/application_security/software_composition_analysis/)
- [SCA Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
