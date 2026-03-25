# Security Sandbox Suite

> **WARNING: This project intentionally contains security vulnerabilities.**
> It is designed for testing and learning with Datadog Security products.
> Do NOT deploy to production or expose to the internet.

Full-suite Datadog Security product testing environment. Run locally with Docker Compose.

**Status:** Local stack is fully functional.

## What's Covered

| Product | How |
|---------|-----|
| **AAP** (App & API Protection) | 4 vulnerable web apps with `DD_APPSEC_ENABLED` |
| **IAST** | Same apps with `DD_IAST_ENABLED`, tainted data flows |
| **SCA** | Pinned vulnerable deps, `DD_APPSEC_SCA_ENABLED` |
| **SAST** | App source code has intentional vulns (scan target) |
| **CWS** (Workload Protection) | Agent with system-probe, trigger scripts |
| **Cloud SIEM** | Local event generator producing fake CloudTrail + Okta logs |

## Prerequisites

Make sure you have these installed before starting:

| Requirement | How to verify | Notes |
|-------------|--------------|-------|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | `docker info` | Must be open and running, not just installed |
| [Git](https://git-scm.com/) | `git --version` | |
| Datadog API Key | [Get one here](https://app.datadoghq.com/organization-settings/api-keys) | Required. App Key is optional (see `.env.example`). |
| Python 3 (optional) | `python3 --version` | Only needed for the SIEM event generator |

If you only want to test a specific product, check the [`playbooks/`](playbooks/) folder for per-product guides.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/eoghanm2013/security-sandbox-suite.git
cd security-sandbox-suite

# 2. Run the interactive setup (creates .env, asks for API key and products)
./scripts/up.sh
```

The startup script will:
1. Create `.env` and ask for your `DD_API_KEY` (first run only)
2. Show a product menu where you pick what to test
3. Optionally start traffic generators
4. Launch only the containers you need

To skip the menu and start everything: `./scripts/up.sh --all`

## Architecture

```
localhost:8080 (nginx gateway)
  /py/   -> python-app:8001   (Flask + dd-trace-py)
  /node/ -> node-app:8002     (Express + dd-trace-js)
  /java/ -> java-app:8003     (Spring Boot + dd-java-agent)
  /php/  -> php-app:8004      (Slim + dd-trace-php)

postgres:5432  - Shared database (pre-seeded pet shop data)
redis:6379     - Session store
dd-agent:8126  - Datadog Agent (APM + Logs + CWS + Process + SBOM + Compliance)
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
| `scripts/up.sh` | Interactive startup (pick products, configure .env, launch) |
| `scripts/up.sh --all` | Start everything, no prompts |
| `scripts/down.sh` | Stop everything |
| `scripts/traffic.sh start [profile]` | Start traffic (all/normal/attacks/iast) |
| `scripts/traffic.sh stop` | Stop traffic generators |

## Cleanup

```bash
# Stop all containers
./scripts/down.sh

# Stop and remove volumes (database data, SIEM logs)
./scripts/down.sh -v

# Full cleanup: containers, volumes, and built images
./scripts/down.sh -v --rmi local
```

## Playbooks

See `playbooks/` for per-product guides. Each covers what the sandbox tests, how to verify it's working, and common patterns you can reproduce.

## Disclaimer

This project is for **educational and testing purposes only**. The intentionally vulnerable applications, attack payloads, and detection trigger scripts are provided to help security practitioners learn and test Datadog Security products. The author is not responsible for any misuse.

## License

[MIT](LICENSE)
