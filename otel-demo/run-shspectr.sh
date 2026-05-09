#!/usr/bin/env bash
# Run shspectr with OTel output, sending to the local demo collector.
#
# Prerequisites:
#   1. docker compose up -d   (from this directory)
#   2. mise run build          (from project root)
#
# Usage:
#   sudo ./run-shspectr.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/debug/shspectr"

if [[ ! -f "$BINARY" ]]; then
    echo "Error: shspectr binary not found at $BINARY"
    echo "Run 'mise run build' from the project root first."
    exit 1
fi

echo "Starting shspectr with OTel output → http://localhost:4318"
echo "Open Grafana at http://localhost:3001 to view logs"
echo "Press Ctrl+C to stop"
echo ""

exec "$BINARY" --output otel --otel-endpoint http://localhost:4318
