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

# Source the env file to read WORKSPACE_DIR (strip comments and blank lines).
WORKSPACE_DIR="$(grep -E '^WORKSPACE_DIR=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || true)"
WORKSPACE_DIR="${WORKSPACE_DIR:-./workspace}"
# Expand relative paths to absolute (relative to script dir so they work from anywhere).
if [[ "$WORKSPACE_DIR" != /* ]]; then
    WORKSPACE_DIR="$SCRIPT_DIR/$WORKSPACE_DIR"
fi
# Ensure the workspace directory exists and is owned by the current user.
# Docker creates bind-mount targets as root if they don't exist, which
# blocks writes from the agent user inside the container.
if [[ ! -d "$WORKSPACE_DIR" ]]; then
    mkdir -p "$WORKSPACE_DIR"
    echo "Created workspace directory: $WORKSPACE_DIR"
elif [[ "$(stat -c '%u' "$WORKSPACE_DIR")" != "$USER_UID" ]]; then
    # Docker creates bind-mount targets as root if they don't pre-exist.
    # We can't chown without root — print the fix command instead.
    echo "WARNING: $WORKSPACE_DIR is not owned by you (UID $USER_UID)."
    echo "  Fix with: sudo chown $USER_UID:$USER_GID \"$WORKSPACE_DIR\""
fi

echo "Sandbox setup complete."
echo "  HOST_UID=${USER_UID}  HOST_GID=${USER_GID}"
echo ""
echo "Next steps:"
echo "  1. Edit .env — set AGENT_CLI, WORKSPACE_DIR, REPO_PATHS, and any tokens."
echo "  2. Build:   docker compose -f \"$SCRIPT_DIR/docker-compose.yml\" build agent"
echo "  3. Start:   docker compose -f \"$SCRIPT_DIR/docker-compose.yml\" up -d proxy"
echo "  4. Run:     $SCRIPT_DIR/start.sh"
echo ""
echo "  (swap 'docker compose' for 'podman-compose' if you prefer Podman)"
