#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE_DIR="$(dirname "$SCRIPT_DIR")"

echo "Stopping Bits & Bytes Pet Shop sandbox..."
cd "$SUITE_DIR"
docker compose -f docker-compose.yml -f docker-compose.traffic.yml down "$@"
echo "All services stopped."
