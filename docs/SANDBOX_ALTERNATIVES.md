# Execution-Plane Sandbox Alternatives — Fence vs cplt

Spektralia is the **data plane** of a layered endpoint stack (see
[docs/ENDPOINT_STACK.md](ENDPOINT_STACK.md)). The **execution plane** — the kernel-enforced
backstop that contains what a tool call actually *does* against the OS — is supplied by a
neighbor sandbox. [`docs/ENDPOINT_STACK.md`](ENDPOINT_STACK.md) documents
[**Fence**](https://github.com/fencesandbox/fence) in that role. This document presents
[**navikt/cplt**](https://github.com/navikt/cplt) as an alternative and lays out the trade-offs
**so the operator can choose** — it does not recommend one over the other.

See also: [docs/ENDPOINT_STACK.md](ENDPOINT_STACK.md) | [docs/THREATS.md](THREATS.md) | [SPEC.md](SPEC.md)

---

## What cplt is

cplt is a kernel-enforced sandbox **purpose-built to wrap AI coding agents** (Claude Code, Copilot
CLI, OpenCode, Gemini CLI, and others). It ships as a single Rust binary — no Docker, no VM — and
enforces three layers:

1. **Kernel sandbox** — blocks file access, process execution, and network ports.
   Linux: Landlock LSM + seccomp-BPF (kernel 5.13+; network filtering 6.7+).
   macOS: Apple Seatbelt/SBPL via `sandbox-exec`.
2. **Network proxy** — filters outbound connections **by domain and port** (not just on/off).
3. **Command guards** — intercept destructive `git`/`gh` operations (push-to-main, merge, etc.).

It blocks reads of `~/.ssh`, `~/.aws`, `~/.kube`, `.env*`, `.pem`, `.key`; denies temp-dir
write-then-exec; filters env vars to an allowlist; and injects `npm_config_ignore_scripts=true` to
defang postinstall supply-chain hooks. Policy is split between a global
`~/.config/cplt/config.toml` and a **committed, per-repo `.cplt.toml`** with deny-by-default
`[deny]` (auto-applied) and `[propose]` (approved on the endpoint via `cplt trust accept`).

---

## Comparison

| Dimension | **Fence** | **cplt** |
|-----------|-----------|----------|
| Platforms | **Linux only** (`bubblewrap`) | **Linux + macOS** (Landlock+seccomp / Seatbelt) |
| Kernel mechanism | namespaces + `landlock` + `seccomp` | Landlock + seccomp-BPF (Linux); Seatbelt/SBPL (macOS) |
| Network model | **default-deny network namespace** (all-or-nothing) | **domain/port-filtering proxy** (granular egress) |
| git/gh guards | none (that is Prempti's job in the stack) | **built-in** command guards |
| Credential-file blocking | via directory allowlist | explicit deny of `~/.ssh`, `~/.aws`, `.env*`, `.pem`, `.key` |
| Env hardening | — | env-var allowlist + `npm_config_ignore_scripts=true` |
| Config model | manual allowlist | global `config.toml` + committed `.cplt.toml` (deny / propose / trust) |
| Agent-awareness | generic process sandbox | purpose-built for coding agents; transparent wrapping |
| Known limitations | Linux-only | Landlock is allowlist-only (cannot deny a subpath inside an allowed dir); macOS Seatbelt deprecation risk; no read-only/full-access presets |

Two facts dominate the choice. **cplt is the only option that runs on macOS** — Fence's
`bubblewrap` is Linux-only, so a macOS endpoint that wants an execution plane needs cplt. And
**cplt's egress proxy is finer-grained than Fence's namespace**: Fence is on/off at the network
boundary, while cplt can permit specific domains/ports — narrowing (not closing) the
"covert channel within an allowlisted destination" gap.

---

## The overlap seam — cplt vs Prempti

In the documented three-tool stack, **Prempti** (the Falco control plane) owns intent policy,
including git/gh guards, and **Fence** owns execution containment. cplt's command guards and egress
proxy **overlap Prempti's control plane**. This is an operator choice, not a recommendation:

- **cplt + Prempti.** Keep both. cplt's git guards and Prempti's Falco rules are redundant — and
  redundancy is fine here, because the stack's rule is **OR-to-block** (any layer can deny; none
  can unilaterally pass). The cost is two policy surfaces to maintain.
- **cplt alone (absorbing Prempti's git role).** Adopt cplt's command guards as the git/gh policy
  and drop Prempti, collapsing the stack from three tools to two on that endpoint. The cost is
  losing Falco's broader rule engine (Prempti sees *every* `PreToolUse`, not just git/gh), so
  weigh what intent policy you give up.

Either way, **Spektralia's data plane is unchanged** — neither cplt nor Prempti reads prompt/tool
*content*; that is what Spektralia does.

---

## The cplt allowlist the stack requires

The analog of [ENDPOINT_STACK.md § "Fence allowlist the stack requires"](ENDPOINT_STACK.md). With
the agent running inside cplt, the following must be explicitly permitted or Spektralia cannot
function:

- **Ollama endpoint** — `127.0.0.1:11434` (TCP) **or** the UDS socket path. cplt's network proxy
  *and* its Landlock rules must allow it, or Spektralia's classifier is unreachable and the gate
  fails closed on every call.
- **`~/.spektralia/` writable** — the hash-chained audit log, `audit.state`, and the `FREEZE`
  file live here. **Confirm cplt's `.env*` / `.key` / `.pem` deny globs do not match anything
  under `~/.spektralia/`** (they currently do not — but audit anything you add there).
- **Project working directory writable**; everything else denied (cplt's default).
- **Prempti's Unix socket** — only if you are retaining Prempti (see the overlap seam above).

**Hash-pinning lifecycle.** `.cplt.toml` is committed and team-edited — the `[propose]` /
`cplt trust accept` flow is *designed* to evolve — so pinning its hash means every legitimate bump
ships drift to endpoints. Therefore Spektralia's preflight (below) is **detect-only by default**
(`sandbox_config_hash` unset): it asserts the wrapper exists and prints the current hash but never
blocks on drift. **Hash-pinning is opt-in** for high-assurance endpoints; rotation is just reading
the value `spektralia check-sandbox` prints and updating the pin. This mirrors Spektralia's
existing `pattern_hash` / `model_digest` lifecycle and avoids a default-on footgun.

---

## Residual gaps

Choosing cplt narrows the gap; it does not close it:

- **In-project secrets stay readable.** Landlock is allowlist-only and cannot deny a subpath
  *inside* an allowed directory — a secret file committed in the project tree is still readable by
  the agent. **Spektralia's content layer remains required** to catch it surfacing into context.
- **macOS Seatbelt deprecation risk.** Apple has signaled `sandbox-exec` may be deprecated; the
  macOS enforcement path is less durable than the Linux one.
- **Covert channels within proxy-allowed domains.** Exfiltration over a domain cplt's proxy
  permits is not caught at the network layer — the same class of gap ENDPOINT_STACK notes for
  Fence's allowlisted destinations.

---

## Wiring it into Spektralia's preflight

Spektralia can assert whichever execution-plane sandbox you chose is actually present, realizing
the [ENDPOINT_STACK.md "cross-layer integrity" roadmap item](ENDPOINT_STACK.md). Configure the
backend, then `spektralia check-sandbox` (run automatically at `SessionStart`) verifies it:

```toml
# .spektralia.toml  →  [spektralia]
sandbox_backend = "cplt"            # "none" (default) | "fence" | "cplt"
# sandbox_config_paths = [".cplt.toml", "~/.config/cplt/config.toml"]   # optional override
# sandbox_config_hash = "<sha256>"  # optional: pin for high-assurance endpoints (else detect-only)
```

Or via environment: `SPEKTRALIA_SANDBOX_BACKEND=cplt`, `SPEKTRALIA_SANDBOX_CONFIG_HASH=<sha256>`.

```bash
spektralia check-sandbox
# backend "none"            -> "OK: no sandbox configured"            (exit 0; default, non-breaking)
# wrapper missing on PATH   -> "FAIL: cplt not on PATH"              (exit 1; SessionStart blocks)
# present, detect-only      -> "OK: cplt present, config <hash[:12]>"(exit 0)
# present, pin mismatch     -> "FAIL: cplt config hash drift ..."    (exit 1; SessionStart blocks)
```

Fail-closed: when a backend is configured, a missing wrapper or drifted pin blocks the session —
the same posture the rest of the stack holds. With the default `none`, behavior is unchanged.
