# CWS (Workload Protection) Investigation Playbook

## What is CWS?

CWS (Cloud Workload Security, now called Workload Protection) monitors what processes, files, and network connections are happening inside your containers and hosts at the kernel level. It uses eBPF (a Linux kernel technology) to watch for suspicious behavior like crypto-miner processes, reverse shells, unauthorized file modifications, or attempts to access cloud metadata endpoints.

**How it differs from AAP:** AAP watches HTTP traffic going into your app. CWS watches the operating system itself. If someone gains access to a container and runs `whoami` or tries to download a crypto-miner, CWS detects that, even though it has nothing to do with HTTP requests.

**How it works in this sandbox:** The Datadog Agent runs with system-probe enabled, which loads eBPF programs into the Docker Desktop Linux VM's kernel. A trigger script simulates common attack patterns (recon commands, crypto-miner DNS lookups, reverse shell attempts) inside a container. The agent detects these and reports them as CWS signals.

## Quick Start

Select option `5` (CWS) or `7` (All) when running:

```bash
./scripts/up.sh
```

Then run the trigger script inside one of the app containers:

```bash
docker compose exec python-app bash -c \
  "apt-get update && apt-get install -y netcat-openbsd dnsutils && bash /dev/stdin" \
  < cws/trigger-detections.sh
```

## Verify It's Working

1. Confirm system-probe is active:

```bash
docker compose exec dd-agent agent status 2>&1 | grep -A 3 "CWS"
```

2. Open **Datadog > Security > Workload Security**
3. Look for signals from host `sandbox-suite`
4. Signals should appear within 2-5 minutes of running the trigger script

## What the Trigger Script Does

The script runs harmless simulations of real attack patterns inside a container. Each one is designed to match a Datadog detection rule.

| Category | What It Simulates | Example |
|----------|------------------|---------|
| Suspicious Process | Attacker running recon commands after gaining access | `whoami`, `id`, `uname -a`, `ps aux` |
| File Integrity (FIM) | Attacker modifying system files to persist | Copies `/etc/passwd`, creates crontab entries, touches SSH config |
| Crypto-miner Patterns | Compromised container mining cryptocurrency | DNS lookups to `pool.minexmr.com`, processes named `xmrig` |
| Reverse Shell | Attacker opening a backdoor connection | `nc` connection attempts, Python socket connects to external IP |
| Metadata Access | Container trying to steal cloud credentials | `curl` to `169.254.169.254` (AWS/GCP/Azure metadata) |
| Privilege Escalation | Attacker trying to gain root | `sudo` attempts, searching for SUID binaries |

You can run individual categories:

```bash
# Just run the crypto-miner simulation
docker compose exec python-app bash -c \
  "apt-get update -qq && apt-get install -y -qq dnsutils > /dev/null && bash /dev/stdin crypto" \
  < cws/trigger-detections.sh
```

## Common Escalation Patterns

### "CWS not detecting process execution"

**What the customer says:** "We see suspicious processes in our containers but CWS isn't generating signals."

**How to investigate:**

1. Check that system-probe is running:

```bash
docker compose exec dd-agent agent status 2>&1 | grep -A 5 "System Probe"
# Should show "Status: Running"
```

2. Check that CWS is enabled:

```bash
docker compose exec dd-agent agent status 2>&1 | grep "feature_cws_enabled"
# Should show: feature_cws_enabled: true
```

3. Run the trigger script and watch for the output (it prints what it's doing)
4. If system-probe isn't running, check logs: `docker compose logs dd-agent 2>&1 | grep -i "system-probe\|cws\|runtime"`

**Common causes:** Missing `pid: host` in docker-compose.yml, missing `/sys/kernel/debug` volume mount, or the kernel not supporting eBPF.

---

### "eBPF probe loading failure"

**What the customer says:** "system-probe fails to start with eBPF errors."

**What this means:** CWS needs to load small programs into the Linux kernel using eBPF. This requires kernel 4.14+ and certain kernel headers or BTF data. On Docker Desktop (Mac/Windows), this usually works because Docker runs a compatible Linux VM. On customer hosts, the kernel may be too old or have security modules (SELinux, AppArmor) blocking eBPF.

**How to check:** `docker compose logs dd-agent 2>&1 | grep -i "ebpf\|probe\|kernel"`

---

### "CWS on Fargate/Windows"

**Not testable locally.** CWS uses eBPF, which requires a Linux kernel. On Fargate and Windows, Datadog offers an "eBPF-less" mode with reduced functionality. If a customer asks about this, escalate with their specific environment details.

## Custom Rules

Custom detection rules are in `cws/custom-rules.yaml`. To load them into the agent:

```bash
docker compose cp cws/custom-rules.yaml dd-agent:/etc/datadog-agent/runtime-security.d/
docker compose restart dd-agent
```

## Troubleshooting

- **system-probe not starting:** Make sure `docker-compose.yml` has `pid: host` and the `/sys/kernel/debug` volume mount on the agent.
- **No signals after trigger script:** Check `docker compose exec dd-agent agent status` for CWS-related errors. Verify rules are loaded (look for "loaded" vs "filtered" in the rule list).
- **Kernel compatibility:** Docker Desktop on Mac/Windows uses a Linux VM that should support eBPF. On bare-metal Linux, kernel 4.14+ is required.

## Reference

- [CWS Documentation](https://docs.datadoghq.com/security/cloud_workload_security/)
- [Custom Rules Guide](https://docs.datadoghq.com/security/cloud_workload_security/agent_expressions/)
- [CWS Troubleshooting](https://docs.datadoghq.com/security/cloud_workload_security/troubleshooting/)
