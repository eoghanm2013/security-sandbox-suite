# SCA (Software Composition Analysis) Investigation Playbook

## What This Tests

Each app pins intentionally vulnerable dependencies. With `DD_APPSEC_SCA_ENABLED=true`, the tracer detects loaded libraries at runtime and reports known CVEs. The dependency manifests also serve as static SCA scan targets.

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

```bash
./scripts/up.sh

# SCA runs automatically on app startup when DD_APPSEC_SCA_ENABLED=true
# Just send some traffic to ensure traces flow
./scripts/traffic.sh start normal
```

## Verify It's Working

1. Open Datadog > Security > Application Security > Vulnerabilities
2. Filter by vulnerability type: "Library Vulnerability"
3. You should see findings for each service's vulnerable dependencies
4. Click a finding to see the affected library, CVE, and severity

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "SCA not detecting vulnerable library" | Check if the library is loaded at runtime | Verify `DD_APPSEC_SCA_ENABLED=true`, check if library is in lock file |
| "SCA shows dev-only deps as runtime" | Compare runtime SCA findings with static scan | Runtime SCA only detects actually-loaded libraries |
| "Severity doesn't match NVD" | Check the specific CVE details | Datadog uses CVSS + EPSS + CISA KEV for scoring |
| "SCA findings disappeared after deploy" | Rebuild container, check dependency versions | Verify the lock file hasn't been updated |

## Troubleshooting

- **No SCA findings:** Confirm `DD_APPSEC_SCA_ENABLED=true`, send some traffic so the tracer reports loaded libraries
- **Partial findings:** Not all package ecosystems have the same CVE coverage. Check Datadog's vulnerability database.
- **Runtime vs static mismatch:** Runtime SCA only sees loaded libraries. Static SCA scans manifests/lock files.

## Reference

- [SCA Documentation](https://docs.datadoghq.com/security/application_security/software_composition_analysis/)
- [SCA Troubleshooting](https://docs.datadoghq.com/security/application_security/troubleshooting/)
