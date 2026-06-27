#!/usr/bin/env bash
# sandbox-entrypoint.sh — FS isolation wrapper using bubblewrap.
#
# Enforces the R/W policy from agent.policy at namespace level:
#   RO: /usr /etc /lib /bin /sbin /home/agent (except writable sub-dirs)
#   RW: /work/workspace /work/outputs /work/session-streams
#   RO: /work/repos
#   RW+exec: /tmp /var/tmp
#   RW: /home/agent/.cache /home/agent/.local /home/agent/.config
#
# Note: this uses Linux user namespaces (bubblewrap), not Landlock LSM.
# True per-path Landlock enforcement is tracked in issue #139.
#
# Falls back to running the command directly when bwrap is not available
# (e.g. inside a CI environment that disallows user namespaces).
set -euo pipefail

AGENT_CMD="${AGENT_CLI:-bash}"

if ! command -v bwrap > /dev/null 2>&1; then
    echo "[sandbox-entrypoint] bwrap not found — running without namespace isolation." >&2
    exec "$AGENT_CMD" "$@"
fi

# Resolve the CLI binary path.
AGENT_BIN="$(command -v "$AGENT_CMD" || true)"
if [ -z "$AGENT_BIN" ] && [ "$AGENT_CMD" != "bash" ]; then
    echo "[sandbox-entrypoint] Agent binary not found: $AGENT_CMD" >&2
    echo "[sandbox-entrypoint] Drop into shell instead? (AGENT_CLI=bash)" >&2
    AGENT_BIN="$(command -v bash)"
fi

exec bwrap \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 2>/dev/null \
    --ro-bind /bin /bin \
    --ro-bind /sbin /sbin \
    --ro-bind /home/agent /home/agent \
    --bind    /home/agent/.cache  /home/agent/.cache \
    --bind    /home/agent/.local  /home/agent/.local \
    --bind    /home/agent/.config /home/agent/.config \
    --bind    /work/workspace     /work/workspace \
    --bind    /work/outputs       /work/outputs \
    --bind    /work/session-streams /work/session-streams \
    --ro-bind /work/repos         /work/repos \
    --tmpfs   /tmp \
    --tmpfs   /var/tmp \
    --proc    /proc \
    --dev     /dev \
    --die-with-parent \
    -- "$AGENT_BIN" "$@"
