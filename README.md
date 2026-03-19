# Security Sandbox Suite

> **WARNING: This project intentionally contains security vulnerabilities.**
> It is designed for testing and learning with Datadog Security products.
> Do NOT deploy to production or expose to the internet.

Full-suite Datadog Security product testing environment. Run locally with Docker Compose, extend to AWS for cloud-only products.

## What's Covered

| Product | Local | AWS | How |
|---------|-------|-----|-----|
| **AAP** (App & API Protection) | Yes | - | 4 vulnerable web apps with `DD_APPSEC_ENABLED` |
| **IAST** | Yes | - | Same apps with `DD_IAST_ENABLED`, tainted data flows |
| **SCA** | Yes | - | Pinned vulnerable deps, `DD_APPSEC_SCA_ENABLED` |
| **SAST** | Yes | - | App source code has intentional vulns (scan target) |
| **CWS** (Workload Protection) | Yes | - | Agent with system-probe, trigger scripts |
| **Cloud SIEM** | Yes | Yes | Local event generator + AWS CloudTrail/GuardDuty |
| **CSPM** | - | Yes | Intentionally misconfigured S3, SG, IAM, EBS |
| **CIEM** | - | Yes | Over-permissioned IAM roles, cross-account access |
| **VM** (Vulnerabilities) | - | Yes | EC2 with vulnerable packages, ECR with vuln images |

## Quick Start

```bash
# 1. Set up your environment
cp .env.example .env
# Edit .env and add your DD_API_KEY

# 2. Start the local stack
./scripts/up.sh

# 3. Open the gateway
open http://localhost:8080

# 4. Start synthetic traffic (normal + attacks + IAST)
./scripts/traffic.sh start

# 5. Check Datadog for signals
#    - APM: Service Catalog > petshop-*
#    - Security: Security > Application Security
#    - CWS: Security > Workload Security
```

## Architecture

```
localhost:8080 (nginx gateway)
  /py/   -> python-app:8001   (Flask + dd-trace-py)
  /node/ -> node-app:8002     (Express + dd-trace-js)
  /java/ -> java-app:8003     (Spring Boot + dd-java-agent)
  /php/  -> php-app:8004      (Slim + dd-trace-php)

postgres:5432  - Shared database (pre-seeded pet shop data)
redis:6379     - Session store
dd-agent:8126  - Datadog Agent (APM + Logs + CWS + Process)
```

## Vulnerable App: Bits & Bytes Pet Shop

Each language implements the same pet supply store with identical vulnerability surfaces:

| Endpoint | Vulnerability | Tests |
|----------|--------------|-------|
| `GET /search?q=` | SQL Injection | AAP WAF, IAST |
| `POST /login` | SQLi + Broken Auth | AAP, IAST |
| `GET /product/:id` | SQLi (numeric) | AAP, IAST |
| `POST /review` | Stored XSS | AAP WAF |
| `GET /profile/:user` | Reflected XSS | AAP WAF |
| `POST /upload` | Path Traversal | AAP, IAST |
| `POST /webhook` | SSRF | AAP, IAST |
| `GET /export?file=` | Command Injection | AAP, IAST |
| `POST /cart/restore` | Insecure Deserialization | IAST |

## Scripts

| Script | What it does |
|--------|-------------|
| `scripts/up.sh` | Start the full local stack |
| `scripts/down.sh` | Stop everything |
| `scripts/traffic.sh start [profile]` | Start traffic (all/normal/attacks/iast) |
| `scripts/traffic.sh stop` | Stop traffic generators |
| `scripts/aws-deploy.sh` | Deploy AWS resources (Terraform) |
| `scripts/aws-destroy.sh` | Tear down AWS resources |

## AWS (On-Demand)

Cloud-only products use Terraform in `terraform/aws/`. Tag your resources appropriately for your environment.

```bash
./scripts/aws-deploy.sh    # Plan + apply
./scripts/aws-destroy.sh   # Destroy when done
```

## Playbooks

See `playbooks/` for per-product guides. Each covers what the sandbox tests, how to verify it's working, and common patterns you can reproduce.

## Disclaimer

This project is for **educational and testing purposes only**. The intentionally vulnerable applications, attack payloads, and detection trigger scripts are provided to help security practitioners learn and test Datadog Security products. The author is not responsible for any misuse.

## License

[MIT](LICENSE)
