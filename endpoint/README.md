# Spektralia Endpoint Stack — Bring-Up

This directory is the deployable **endpoint setup** for the layered stack described in
[`docs/ENDPOINT_STACK.md`](../docs/ENDPOINT_STACK.md) and
[`docs/SANDBOX_ALTERNATIVES.md`](../docs/SANDBOX_ALTERNATIVES.md). It composes three planes on
one developer workstation running Claude Code:

| Plane | Tool | Artifact here |
|-------|------|---------------|
| **Data** | Spektralia (this repo) | Claude Code hooks + `spektralia.endpoint.toml` |
| **Control** | [Prempti](https://github.com/falcosecurity/prempti) (Falco) | `prempti/spektralia.rules.yaml` |
| **Execution** | [cplt](https://github.com/navikt/cplt) | repo-root [`.cplt.toml`](../.cplt.toml) + `cplt-global-config.toml` |

The recommended posture is **Claude Code launched _inside_ cplt** so the whole agent process
tree — including subprocess shells the hook layer never sees — inherits the sandbox.

## Files

- **`spektralia.endpoint.toml`** — the activated `[spektralia]` config (sandbox + Prempti keys)
  to merge into your real config. The repo-root `spektralia.toml` deliberately stays at the
  non-breaking defaults (`sandbox_backend = "none"`) so Spektralia's own dev workflow is
  unaffected; this file is what flips the stack on.
- **`cplt-global-config.toml`** — copy to `~/.config/cplt/config.toml`. Machine-level cplt
  grants: `agent = "claude"`, Ollama loopback (`localhost = [11434]`), and `~/.spektralia`
  writable.
- **`../.cplt.toml`** — committed per-repo cplt deny/propose policy (read from git HEAD).
- **`prempti/spektralia.rules.yaml`** — Falco rules for the control plane (git/gh guards,
  credential-path and reverse-shell intent denial).
- **`../scripts/run-claude-sandboxed.sh`** — the launcher: preflights, then `exec cplt -- claude`.

## One-time setup

```bash
# 1. Data plane — Spektralia + classifier
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
ollama pull llama3.1:8b

# 2. Wire the Claude Code hooks (writes .claude/settings.json, self-verifies via hook-check)
spektralia install-hooks            # project scope; add --global for ~/.claude/settings.json

# 3. Execution plane — cplt
#    install cplt (see https://github.com/navikt/cplt), then:
cp endpoint/cplt-global-config.toml ~/.config/cplt/config.toml
cplt trust accept --all             # approve this repo's [propose] block in .cplt.toml

# 4. Control plane — Prempti (optional but recommended)
#    install Prempti (Falco), then point it at the rules:
mkdir -p ~/.prempti && cp endpoint/prempti/spektralia.rules.yaml ~/.prempti/rules.yaml

# 5. Activate the stack in Spektralia's config
#    either merge endpoint/spektralia.endpoint.toml into spektralia.toml, or export:
export SPEKTRALIA_SANDBOX_BACKEND=cplt
export SPEKTRALIA_PREMPTI_BACKEND=prempti
export SPEKTRALIA_PREMPTI_SOCKET=~/.prempti/prempti.sock
```

## Verify

```bash
spektralia check-ollama     # OK: Ollama <version>
spektralia check-sandbox    # OK: cplt present, config <hash>   (FAIL if cplt missing — fail-closed)
spektralia check-prempti    # OK: prempti present, ...          (FAIL if premptictl/socket missing)
spektralia hook-check       # OK: all required hooks present
```

All four are exactly what the `SessionStart` hook runs; once they pass, a session is clean to start.

## Launch

```bash
scripts/run-claude-sandboxed.sh                 # interactive
scripts/run-claude-sandboxed.sh -- -p "..."     # one-shot; args after -- go to Claude Code
```

## Posture

Fail-closed across all three planes. With a backend configured, a missing wrapper, a dead
Prempti socket, or a drifted config-hash pin **blocks the session** — uncertainty in one plane
is never silently covered by another. To pin cplt/Prempti config for high-assurance endpoints,
read the hash `check-sandbox` / `check-prempti` prints and set `sandbox_config_hash` /
`prempti_config_hash` (detect-only until you do). See the docs for the full rationale and the
residual gaps the stack still does not close.
