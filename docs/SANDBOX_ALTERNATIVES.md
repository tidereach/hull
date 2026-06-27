# Execution-Plane Sandbox Alternatives — Fence vs cplt vs cplt-sndbx

Spektralia is the **data plane** of a layered endpoint stack (see
[docs/ENDPOINT_STACK.md](ENDPOINT_STACK.md)). The **execution plane** — the kernel-enforced
backstop that contains what a tool call actually *does* against the OS — is supplied by a
neighbor sandbox. [`docs/ENDPOINT_STACK.md`](ENDPOINT_STACK.md) documents
[**Fence**](https://github.com/fencesandbox/fence) in that role. This document presents
[**navikt/cplt**](https://github.com/navikt/cplt) and **cplt-sndbx** (the v1 preferred backend,
lives in `infra/sandbox/`) as alternatives and lays out the trade-offs.

**v1 recommendation: cplt-sndbx** — it is the only option that ships with a Squid egress
allowlist, per-path FS isolation, the session-streams Airlock contract, and a working Spektralia
hook layer out of the box. Fence and navikt/cplt are documented here for operators who cannot use
Podman/Docker or who are evaluating the broader option space.

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

## cplt-sndbx (preferred v1 backend)

cplt-sndbx is a **Podman/Docker Compose stack** that lives in `infra/sandbox/`. It is the
recommended execution-plane backend for teams already running Linux + Podman/Docker:

- **Hardened compose stack** — two services: a Squid egress proxy (the only service with external
  network access) and the agent container (internal-only network, forced through proxy).
- **Read-only rootfs** — `read_only: true` on the agent service; `/tmp`, `~/.cache`, `~/.local`
  are tmpfs; source repos are mounted `:ro` by default; only the active workspace is `:rw`.
- **Named volumes** — `agent-config`, `agent-outputs`, `session-streams` (named, not host binds,
  eliminating the parallel-instance collision in the upstream outline).
- **Namespace isolation** — `entrypoint.sh` wraps the agent CLI in `bwrap` enforcing the policy
  from `landlock/agent.policy`. True Landlock LSM is a follow-up (#139, pending landrun
  verification).
- **Session-streams Airlock feed** — the Stop hook writes normalized JSONL turn events to
  `/work/session-streams/<session_id>.jsonl` (backed by the `session-streams` named volume).
  This is the contract the Airlock ingester (#114) consumes.
- **Agent-CLI selector** — `AGENT_CLI=copilot|claude|none` build ARG; choose at build time,
  not image time.

`spektralia check-sandbox --backend cplt-sndbx` asserts `podman` or `docker` is on PATH and the
`infra/sandbox/` config files match the expected hash. Set `SPEKTRALIA_SANDBOX_OFFLINE=1` to bypass
the check in CI or offline environments.

### Follow-up items (v2 scope)
- **#138** Custom seccomp profile restricting kernel-attack syscalls.
- **#139** True Landlock LSM (per-path R/W at kernel level via landrun or equivalent).
- **#140** gVisor (`runsc`) runtime for syscall-level isolation.
- **#142** Prempti sidecar for intent-layer control.

---

## Comparison

| Dimension | **Fence** | **navikt/cplt** | **cplt-sndbx** |
|-----------|-----------|---------|---------|
| Platforms | **Linux only** (`bubblewrap`) | **Linux + macOS** | Linux + macOS (Podman/Docker) |
| Kernel mechanism | namespaces + Landlock + seccomp | Landlock + seccomp-BPF / Seatbelt | compose read_only + bwrap namespaces (#139: Landlock LSM planned) |
| Network model | default-deny namespace | domain/port-filtering proxy | **Squid domain-allowlist proxy** (same pattern, ships with curated lists) |
| git/gh guards | none | built-in | none (Prempti scope) |
| Credential-file blocking | directory allowlist | explicit deny list | `:ro` repo mounts + bwrap R/W boundary |
| Session stream | none | none | **JSONL to `session-streams` named volume** (Airlock substrate) |
| Spektralia baked in | no | no | **yes** (built into image at compose-build time) |
| Agent-CLI selector | no | no | **`AGENT_CLI=copilot\|claude\|none`** |
| v1 preferred | — | — | **yes** |

Two facts from the original comparison still stand. **navikt/cplt is the only option that runs on
macOS without Docker** — Fence's `bubblewrap` is Linux-only, and cplt-sndbx requires
Podman/Docker. And **cplt's egress proxy is finer-grained than Fence's namespace**: Fence is
on/off at the network boundary, while cplt and cplt-sndbx both permit specific domains/ports.

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
sandbox_backend = "cplt-sndbx"      # "none" (default) | "fence" | "cplt" | "cplt-sndbx"
# sandbox_config_hash = "<sha256>"  # optional: pin for high-assurance endpoints (else detect-only)
```

Or via environment: `SPEKTRALIA_SANDBOX_BACKEND=cplt-sndbx`, `SPEKTRALIA_SANDBOX_CONFIG_HASH=<sha256>`.

```bash
spektralia check-sandbox
# backend "none"                -> "OK: no sandbox configured"                  (exit 0)
# cplt-sndbx, podman missing    -> "FAIL: neither podman nor docker found"      (exit 1)
# cplt-sndbx, files missing     -> "FAIL: infra/sandbox config files not found" (exit 1)
# cplt-sndbx, all ok            -> "OK: cplt-sndbx ready, config <hash[:12]>"   (exit 0)
# SPEKTRALIA_SANDBOX_OFFLINE=1  -> "OK: cplt-sndbx offline mode"               (exit 0)
```

Fail-closed: when a backend is configured, a missing wrapper or drifted pin blocks the session —
the same posture the rest of the stack holds. With the default `none`, behavior is unchanged.
