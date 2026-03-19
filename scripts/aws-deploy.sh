#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$(dirname "$SCRIPT_DIR")/terraform/aws"

if ! command -v terraform &>/dev/null; then
    echo "ERROR: terraform not found. Install it first."
    exit 1
fi

if ! command -v aws &>/dev/null; then
    echo "ERROR: aws CLI not found. Install it first."
    exit 1
fi

CREATOR="${TF_VAR_creator:-$(whoami)}"

echo "Deploying Security Sandbox AWS resources..."
echo "  Tags: creator=${CREATOR}"
echo ""

cd "$TF_DIR"

cleanup() { rm -f tfplan; }
trap cleanup INT TERM

terraform init -upgrade
terraform plan -out=tfplan

echo ""
read -p "Apply this plan? (yes/no): " CONFIRM
if [ "$CONFIRM" = "yes" ]; then
    terraform apply tfplan
    echo ""
    echo "AWS resources deployed. Run './scripts/aws-destroy.sh' to tear down."
else
    echo "Cancelled."
    rm -f tfplan
fi
