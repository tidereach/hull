#!/usr/bin/env bash
#
# run-claude-sandboxed.sh — launch Claude Code inside the endpoint stack.
#
# This is the recommended posture from docs/ENDPOINT_STACK.md ("option 2 — launch Claude
# Code inside the sandbox"): the whole agent process tree, including every subprocess shell
# the hook layer never sees, inherits the cplt sandbox. Spektralia (data plane) runs as
# Claude Code hooks; Prempti (control plane) and Ollama run as host services outside the
# sandbox and are reached over the allowlisted loopback / IPC.
#
# Order of operations:
#   1. Run the same preflights SessionStart enforces, so failures surface before launch.
#   2. exec cplt, which wraps the configured agent (set `agent = "claude"` in
#      ~/.config/cplt/config.toml — see endpoint/cplt-global-config.toml).
#
# Anything after `--` (or any args to this script) is passed through to Claude Code.
#
# Usage:
#   scripts/run-claude-sandboxed.sh [claude args...]
#   scripts/run-claude-sandboxed.sh -- -p "summarize the diff"

set -euo pipefail

SPEKTRALIA="${SPEKTRALIA_BIN:-spektralia}"

echo "spektralia endpoint: preflight" >&2

# Fail closed: if any preflight the SessionStart hook would run fails here, do not launch.
"$SPEKTRALIA" check-ollama
"$SPEKTRALIA" check-sandbox
"$SPEKTRALIA" check-prempti

if ! command -v cplt >/dev/null 2>&1; then
    echo "FAIL: cplt not on PATH — install the execution-plane sandbox first" >&2
    echo "      see docs/SANDBOX_ALTERNATIVES.md and endpoint/README.md" >&2
    exit 1
fi

echo "spektralia endpoint: launching Claude Code inside cplt" >&2

# Strip a leading `--` so `run-claude-sandboxed.sh -- <args>` and
# `run-claude-sandboxed.sh <args>` behave identically.
if [[ "${1:-}" == "--" ]]; then
    shift
fi

# cplt launches the agent configured in [sandbox] agent = "claude"; everything after `--`
# is forwarded to that agent.
exec cplt -- "$@"
