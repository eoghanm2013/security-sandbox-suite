#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$(dirname "$SCRIPT_DIR")/terraform/aws"

echo "WARNING: This will destroy all Security Sandbox AWS resources."
echo ""

cd "$TF_DIR"

terraform plan -destroy

echo ""
read -p "Destroy these resources? (yes/no): " CONFIRM
if [ "$CONFIRM" = "yes" ]; then
    terraform destroy -auto-approve
    echo "All AWS resources destroyed."
else
    echo "Cancelled."
fi
