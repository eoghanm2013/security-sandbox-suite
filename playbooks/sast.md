# SAST (Static Application Security Testing) Investigation Playbook

## What This Tests

The app source code under `apps/` contains intentional SAST-detectable vulnerabilities: hardcoded secrets, raw SQL concatenation, eval/exec usage, insecure deserialization, and command injection patterns. These serve as scan targets for Datadog SAST.

### Intentional SAST Findings in Source Code

| Finding Type | Where | Example |
|-------------|-------|---------|
| Hardcoded secret | All apps | `SECRET_KEY = "BITS_AND_BYTES_SUPER_SECRET_KEY_2024"` |
| Hardcoded API key | All apps | `INTERNAL_API_TOKEN = "sk_live_dd_internal_api_token_never_commit"` |
| Hardcoded DB password | All apps | `petshop123` in connection strings |
| SQL injection | `/search`, `/login`, `/product` routes | `f"SELECT * FROM users WHERE username='{username}'"` |
| Command injection | `/export` route | `subprocess.check_output(f"cat /tmp/uploads/{filename}", shell=True)` |
| Insecure deserialization | `/cart/restore` route | `pickle.loads(...)`, `eval(...)`, `unserialize(...)` |
| Path traversal | `/upload` route | `os.path.join("/tmp/uploads", user_filename)` |
| SSRF | `/webhook` route | `urllib.request.urlopen(user_url)` |

## Quick Start

SAST doesn't require running containers. It scans source code directly.

**Option A: Datadog-hosted scanning**
Configure the `apps/` directory as a repository in Datadog's Code Security settings.

**Option B: CI/CD scanning**
Add Datadog SAST to your GitHub Actions pipeline to scan on push.

**Option C: Local verification**
Review the source code directly to verify the vulnerability patterns exist.

## Verify It's Working

1. Open Datadog > Security > Code Security > Static Analysis
2. Look for findings in the scanned repository
3. Findings should include hardcoded secrets, SQL injection, command injection, etc.

## Common Escalation Patterns

| Escalation Type | How to Reproduce | What to Check |
|----------------|-----------------|---------------|
| "SAST not finding known vulnerability" | Verify the vuln pattern exists in source | Check supported languages, rule coverage |
| "False positive on hardcoded string" | Review the specific finding and context | Check if string is actually a secret vs. a config default |
| "SAST scan failing in CI" | Check CI logs for the SAST scanner | Verify API key, supported CI provider |
| "Different findings between hosted and CI scan" | Compare scan configurations | Check rule sets, file exclusion patterns |

## Troubleshooting

- **No findings after scan:** Verify the language is supported, check scan logs for errors
- **Too many false positives:** Review rule severity settings, configure suppressions
- **Scan taking too long:** Check repository size, consider excluding test/vendor directories

## Reference

- [SAST Documentation](https://docs.datadoghq.com/security/application_security/code_security/static_analysis/)
- [SAST Troubleshooting](https://docs.datadoghq.com/security/application_security/code_security/static_analysis/)
