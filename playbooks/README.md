# Investigation Playbooks

Per-product guides for using the Security Sandbox Suite to test and reproduce issues with Datadog Security products. Each playbook covers what the sandbox tests, how to bring it up, how to verify it's working, and common patterns you can reproduce.

## Quick Reference

| Playbook | Product | Primary Use Case |
|----------|---------|-----------------|
| [aap.md](aap.md) | App & API Protection | WAF detection, attack blocking, IP/user blocking |
| [iast.md](iast.md) | IAST | Source-to-sink taint tracking, exploitable code paths |
| [sca.md](sca.md) | SCA | Vulnerable dependency detection (runtime + static) |
| [sast.md](sast.md) | SAST | Static code scanning for hardcoded secrets, SQLi patterns |
| [cws.md](cws.md) | Workload Protection | Process monitoring, FIM, container security |
| [siem.md](siem.md) | Cloud SIEM | Detection rules, log pipelines, signals |
| [agent-memory.md](agent-memory.md) | Agent Memory | Memory impact investigation when security features enabled |

## How to Use

1. Pick the product you want to test
2. Open the corresponding playbook
3. Follow "Quick Start" to bring up relevant components
4. Use "Common Escalation Patterns" to reproduce known issues
5. Compare sandbox behavior against what you expect
6. If behavior differs from docs, you may have found a bug
