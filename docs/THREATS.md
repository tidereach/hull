# Spektralia — Threat Model

Spektralia is a local pre-cloud sensitivity gate. This document enumerates
the attacker models it is designed to resist and the surfaces it explicitly
does not cover.

See also: [docs/COMPLIANCE.md](COMPLIANCE.md) | [SPEC.md §2](../SPEC.md)

---

## In-scope threats

**PII / credentials / internal identifiers in cloud LLM payloads.** Both content
the user types directly and content that tools surface (file reads, shell command
output, MCP tool outputs) may contain sensitive data. Spektralia intercepts both
surfaces: `UserPromptSubmit` covers typed input and `PostToolUse` covers tool
results before they re-enter context.

**Tampering with the gate itself.** Patterns swapped for permissive ones, the
classifier model swapped or backdoored, audit lines deleted, or the freeze file
forged. Integrity is enforced by `pattern_hash`, `model_digest`, and `prompt_hash`
(verified at `SessionStart`), the hash-chained audit log (tamper-evident across
restarts), and canary corpus self-test (backdoored model → drift → auto-freeze).

**Same-UID local processes.** Other processes running as the same user on the same
host. Attack vectors include: binding a TCP port before Ollama starts to intercept
classifier traffic; dropping files into `~/.spektralia/` (freeze file, audit state,
config) to manipulate gate behaviour; reading process memory via `/proc/$pid/mem`
to extract secrets from in-flight data. Mitigations: prefer UDS connection to Ollama
with socket owner and mode checks; `audit.state` uses `fsync` and atomic rename;
freeze file uses `flock`; all state files created at mode 0600; `PR_SET_DUMPABLE=0`
set at import on Linux to reduce `/proc/$pid/mem` exposure.

**Classifier model as adversary.** Backdoored model weights (either substituted at
rest or injected via a compromised Ollama model registry) that return `safe` for
all inputs. The canary corpus runs at startup and on a schedule with random-nonced
payloads to detect this: a model that always-passes will fail canary and trigger
auto-freeze. The TCP fallback to Ollama pins both the PID and the binary SHA-256 so
that a substitute process cannot silently replace the expected model server.

**Cloud LLM conversation history as a leak channel above the per-turn gate.**
Each turn is individually gated, but the cloud LLM's growing conversation history
accumulates sanitized tokens across turns. If a model references a sanitized token
in a later context that makes the original value inferrable, or if `/compact`
summarises history that referenced sensitive tokens, the gate's per-turn protection
is undermined. This is documented explicitly; see mitigations in "What this gate
does NOT detect" below.

**User as adversary-of-themselves.** A user who receives repeated block events
may attempt to mutate input until it passes — either by slightly altering sensitive
values to avoid the exact regex, or by operating in soft mode and accepting
repeated overrides. The mutation-until-pass detector in soft mode raises an audit
event and can block after a configurable number of same-category overrides within
a window. Alarm fatigue is mitigated by `--explain` output, which tells the user
specifically what was detected and why, rather than a bare refusal.

---

## Out-of-scope threats

**Network MITM on the Anthropic API.** Spektralia gates what leaves the local
machine into the Claude Code process. It does not inspect or authenticate the
TLS channel between Claude Code and the Anthropic API endpoint.

**Kernel-level / root / CAP_SYS_PTRACE local attackers.** A process with root
privileges or `CAP_SYS_PTRACE` can inspect any process's memory regardless of
`PR_SET_DUMPABLE`. Kernel-level defence is outside the scope of a user-space gate.

**Side-channels across tenants.** Timing, cache, or speculative-execution
side-channels between co-located users or VMs are not addressed.

**Attacks on the Ollama binary itself.** Spektralia pins the Ollama server's PID
and binary SHA-256 over the TCP fallback, but a sufficiently privileged attacker
who replaces the binary on disk and restarts it before the pin is recorded is
out of scope. The UDS path with socket-owner checks provides stronger isolation
against this class of attack in practice.

---

## What this gate does NOT detect

**Contextual PII in prose.** Names, postal addresses, and free-text identifiers that
are not capturable by pattern matching are not detected. Named-Entity Recognition
(NER) using a local model (e.g., spaCy) is a v2 roadmap item. Deployers handling
data that includes natural-language references to individuals should treat this as
a known gap.

**Model outputs / assistant turns.** The gate operates on inputs (user prompts and
tool outputs) before they reach the model. The model's own responses are not
inspected — gating the prose response stream in real time is the wrong surface and
would create a re-identification feature if tokens were restored.

**`/compact` summarisation.** Claude Code's `/compact` command summarises the
conversation history at the application layer, above the API boundary. The gate
does not see the summary content. Avoid `/compact` in sessions that have processed
sensitive content; start a fresh session instead.

**Attachments in Claude Code prompts.** Attachments are refused by default. Use
`--allow-attachments` to opt in; note that attachment content will then be subject
to the same gate as any other input, but the gate's coverage of attachment file
formats (binary, rich text, compressed archives) is limited in v1.

---

## Posture

Fail-closed throughout. If any component cannot make a confident "safe" decision,
block. Classifier unavailable → block (unless `SPEKTRALIA_FAIL_OPEN=1`). ReDoS
timeout on a regex → `REGEX_TIMEOUT` sentinel → block. Canary drift → auto-freeze
→ all subsequent calls block. `SessionStart` integrity check fails → block.
