#!/usr/bin/env bash
# setup.sh — Populate .env with host UID/GID and optional repo paths.
# Run once before building the container.
#
# Usage: ./setup.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    echo "Created .env from .env.example"
fi

USER_UID="$(id -u)"
USER_GID="$(id -g)"

# Update HOST_UID and HOST_GID in .env
sed -i "s/^HOST_UID=.*/HOST_UID=${USER_UID}/" "$ENV_FILE"
sed -i "s/^HOST_GID=.*/HOST_GID=${USER_GID}/" "$ENV_FILE"

echo "Sandbox setup complete."
echo "  HOST_UID=${USER_UID}  HOST_GID=${USER_GID}"
echo ""
echo "Next steps:"
echo "  1. Edit .env — set AGENT_CLI, WORKSPACE_DIR, REPO_PATHS, and any tokens."
echo "  2. Build:   podman-compose -f \"$SCRIPT_DIR/docker-compose.yml\" build agent"
echo "  3. Start:   podman-compose -f \"$SCRIPT_DIR/docker-compose.yml\" up -d proxy"
echo "  4. Run:     podman-compose -f \"$SCRIPT_DIR/docker-compose.yml\" run --rm agent"
