#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE_DIR="$(dirname "$SCRIPT_DIR")"
SUITE_ENV="$SUITE_DIR/.env"

if [ ! -f "$SUITE_ENV" ]; then
    echo "ERROR: No .env file found."
    echo ""
    echo "Create one from the example:"
    echo "  cp .env.example .env"
    echo ""
    echo "Then fill in your DD_API_KEY (and optionally DD_APP_KEY)."
    exit 1
fi

if ! grep -q '^DD_API_KEY=.\+' "$SUITE_ENV"; then
    echo "ERROR: DD_API_KEY is empty in .env"
    echo "Set your Datadog API key in .env and try again."
    exit 1
fi

echo "Starting Bits & Bytes Pet Shop sandbox..."
cd "$SUITE_DIR"
docker compose up -d --build

echo ""
echo "Services:"
echo "  Gateway:  http://localhost:8080"
echo "  Python:   http://localhost:8001"
echo "  Node:     http://localhost:8002"
echo "  Java:     http://localhost:8003"
echo "  PHP:      http://localhost:8004"
echo "  Agent:    http://localhost:8126 (APM)"
echo ""
echo "Run './scripts/traffic.sh start' to begin synthetic traffic."
