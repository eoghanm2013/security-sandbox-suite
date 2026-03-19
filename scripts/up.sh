#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE_DIR="$(dirname "$SCRIPT_DIR")"
SUITE_ENV="$SUITE_DIR/.env"

# ── .env bootstrap ──────────────────────────────────────────────────────────
if [ ! -f "$SUITE_ENV" ]; then
    echo "No .env file found. Creating from .env.example..."
    cp "$SUITE_DIR/.env.example" "$SUITE_ENV"
    echo ""
    read -rp "Enter your DD_API_KEY: " api_key
    if [ -z "$api_key" ]; then
        echo "ERROR: DD_API_KEY is required."
        exit 1
    fi
    sed -i.bak "s/^DD_API_KEY=.*/DD_API_KEY=${api_key}/" "$SUITE_ENV"
    rm -f "$SUITE_ENV.bak"
    echo "Saved to .env"
    echo ""
fi

if ! grep -q '^DD_API_KEY=.\+' "$SUITE_ENV"; then
    echo "ERROR: DD_API_KEY is empty in .env"
    echo "Set your Datadog API key in .env and try again."
    exit 1
fi

# ── Helper: update a key in .env ────────────────────────────────────────────
set_env() {
    local key="$1" val="$2"
    if grep -q "^${key}=" "$SUITE_ENV"; then
        sed -i.bak "s|^${key}=.*|${key}=${val}|" "$SUITE_ENV"
        rm -f "$SUITE_ENV.bak"
    else
        echo "${key}=${val}" >> "$SUITE_ENV"
    fi
}

# ── Non-interactive mode ────────────────────────────────────────────────────
if [ "${1:-}" = "--all" ]; then
    set_env DD_APPSEC_ENABLED true
    set_env DD_IAST_ENABLED true
    set_env DD_APPSEC_SCA_ENABLED true
    set_env DD_SYSTEM_PROBE_ENABLED true
    set_env DD_RUNTIME_SECURITY_CONFIG_ENABLED true

    echo "Starting everything..."
    cd "$SUITE_DIR"
    docker compose --profile apps --profile siem up -d --build
    echo ""
    echo "All products enabled. Gateway: http://localhost:8080"
    echo "Run './scripts/traffic.sh start' for synthetic traffic."
    exit 0
fi

# ── Interactive product selection ───────────────────────────────────────────
echo "╔══════════════════════════════════════════════╗"
echo "║       Security Sandbox Suite                 ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Which products do you want to test?"
echo ""
echo "  [1] AAP   - App & API Protection (WAF, attack detection)"
echo "  [2] IAST  - Tainted data flow analysis"
echo "  [3] SCA   - Vulnerable dependency scanning"
echo "  [4] SAST  - Static code analysis (apps as scan target)"
echo "  [5] CWS   - Workload Protection (eBPF runtime security)"
echo "  [6] SIEM  - Cloud SIEM (OOTB detection rules)"
echo "  [7] All"
echo ""
read -rp "Enter choices (comma-separated, e.g. 1,2,5): " choices

ENABLE_AAP=false
ENABLE_IAST=false
ENABLE_SCA=false
ENABLE_APPS=false
ENABLE_CWS=false
ENABLE_SIEM=false

IFS=',' read -ra PICKS <<< "$choices"
for pick in "${PICKS[@]}"; do
    pick="$(echo "$pick" | tr -d ' ')"
    case "$pick" in
        1) ENABLE_AAP=true;  ENABLE_APPS=true ;;
        2) ENABLE_IAST=true; ENABLE_APPS=true ;;
        3) ENABLE_SCA=true;  ENABLE_APPS=true ;;
        4) ENABLE_APPS=true ;;
        5) ENABLE_CWS=true ;;
        6) ENABLE_SIEM=true ;;
        7) ENABLE_AAP=true; ENABLE_IAST=true; ENABLE_SCA=true
           ENABLE_APPS=true; ENABLE_CWS=true; ENABLE_SIEM=true ;;
        *) echo "Unknown option: $pick"; exit 1 ;;
    esac
done

if [ "$ENABLE_APPS" = "false" ] && [ "$ENABLE_CWS" = "false" ] && [ "$ENABLE_SIEM" = "false" ]; then
    echo "Nothing selected. Exiting."
    exit 0
fi

# ── Ask about traffic ───────────────────────────────────────────────────────
START_TRAFFIC=false
if [ "$ENABLE_APPS" = "true" ]; then
    echo ""
    read -rp "Start synthetic traffic generators? (y/N): " traffic_answer
    case "$traffic_answer" in
        [yY]*) START_TRAFFIC=true ;;
    esac
fi

# ── Write toggles to .env ──────────────────────────────────────────────────
set_env DD_APPSEC_ENABLED "$ENABLE_AAP"
set_env DD_IAST_ENABLED "$ENABLE_IAST"
set_env DD_APPSEC_SCA_ENABLED "$ENABLE_SCA"
set_env DD_SYSTEM_PROBE_ENABLED "$ENABLE_CWS"
set_env DD_RUNTIME_SECURITY_CONFIG_ENABLED "$ENABLE_CWS"

# ── Build docker compose command ────────────────────────────────────────────
cd "$SUITE_DIR"
PROFILES=()
[ "$ENABLE_APPS" = "true" ] && PROFILES+=(--profile apps)
[ "$ENABLE_SIEM" = "true" ] && PROFILES+=(--profile siem)

echo ""
echo "Starting sandbox..."
docker compose "${PROFILES[@]}" up -d --build

if [ "$START_TRAFFIC" = "true" ]; then
    echo ""
    echo "Starting traffic generators..."
    docker compose -f docker-compose.yml -f docker-compose.traffic.yml \
        "${PROFILES[@]}" up -d --build traffic-normal traffic-attacks traffic-iast
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "Running:"
[ "$ENABLE_APPS" = "true" ]  && echo "  Gateway:  http://localhost:8080"
[ "$ENABLE_AAP"  = "true" ]  && echo "  AAP:      enabled (WAF + attack detection)"
[ "$ENABLE_IAST" = "true" ]  && echo "  IAST:     enabled (tainted data flows)"
[ "$ENABLE_SCA"  = "true" ]  && echo "  SCA:      enabled (vulnerable dependencies)"
[ "$ENABLE_APPS" = "true" ]  && echo "  SAST:     apps available as scan targets"
[ "$ENABLE_CWS"  = "true" ]  && echo "  CWS:      enabled (system-probe + runtime security)"
[ "$ENABLE_SIEM" = "true" ]  && echo "  SIEM:     enabled (CloudTrail + Okta events every 5m)"
[ "$START_TRAFFIC" = "true" ] && echo "  Traffic:  running (normal + attacks + iast)"
echo "  Agent:    http://localhost:8126 (APM)"
echo ""
if [ "$ENABLE_APPS" = "true" ] && [ "$START_TRAFFIC" = "false" ]; then
    echo "Run './scripts/traffic.sh start' to begin synthetic traffic."
fi
echo "Run './scripts/down.sh' to stop everything."
