#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
    echo "Usage: $0 {start|stop|status} [profile]"
    echo ""
    echo "Profiles: all, normal, attacks, iast (default: all)"
    echo ""
    echo "Examples:"
    echo "  $0 start           # Start all traffic profiles"
    echo "  $0 start attacks   # Start only attack traffic"
    echo "  $0 stop            # Stop all traffic"
    echo "  $0 status          # Show running traffic containers"
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi

ACTION="$1"
PROFILE="${2:-all}"
cd "$SUITE_DIR"

case "$ACTION" in
    start)
        echo "Starting traffic ($PROFILE)..."
        if [ "$PROFILE" = "all" ]; then
            docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml up -d --build traffic-normal traffic-attacks traffic-iast
        else
            docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml up -d --build "traffic-${PROFILE}"
        fi
        echo "Traffic running."
        ;;
    stop)
        echo "Stopping traffic..."
        docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml stop traffic-normal traffic-attacks traffic-iast 2>/dev/null || true
        docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml rm -f traffic-normal traffic-attacks traffic-iast 2>/dev/null || true
        echo "Traffic stopped."
        ;;
    status)
        docker compose --profile apps -f docker-compose.yml -f docker-compose.traffic.yml ps traffic-normal traffic-attacks traffic-iast 2>/dev/null || echo "No traffic containers running."
        ;;
    *)
        usage
        exit 1
        ;;
esac
