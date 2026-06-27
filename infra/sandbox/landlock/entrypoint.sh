#!/usr/bin/env bash
# sandbox-entrypoint.sh — FS isolation wrapper using bubblewrap.
#
# Enforces the R/W policy from agent.policy at namespace level:
#   RO: /usr /etc /lib /bin /sbin /home/agent (except writable sub-dirs)
#   RW: /work/workspace /work/outputs /work/session-streams
#   RO: /work/repos
#   RW: /tmp /var/tmp /home/agent/.cache /home/agent/.local /home/agent/.config
#
# Always execs "$@" (the Docker CMD) — never resolves AGENT_CLI itself.
# Run: docker compose run --rm agent           → exec bash (default CMD)
#      docker compose run --rm agent copilot   → exec copilot
#
# Note: bwrap uses Linux user namespaces, not Landlock LSM (#139).
# Falls back to direct exec when user namespaces are unavailable (Docker default).
# Docker's own read_only + :ro mounts remain enforced by the container runtime.
set -euo pipefail

# bwrap requires unprivileged user namespaces. Test before committing to exec
# so we fall back cleanly rather than dying with exit code 1.
_can_bwrap() {
    command -v bwrap > /dev/null 2>&1 \
        && bwrap --ro-bind / / --proc /proc --dev /dev -- true 2>/dev/null
}

if ! _can_bwrap; then
    echo "[sandbox-entrypoint] bwrap unavailable (no user-ns permission) — running without namespace isolation." >&2
    exec "$@"
fi

# Build lib64 bind arg only if the path exists (varies by base image).
LIB64_ARG=()
[ -e /lib64 ] && LIB64_ARG=(--ro-bind /lib64 /lib64)

exec bwrap \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --ro-bind /lib /lib \
    "${LIB64_ARG[@]}" \
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
    -- "$@"
