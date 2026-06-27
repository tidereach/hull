#!/usr/bin/env bash
# start.sh — Quick launcher for an interactive agent session.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm agent
