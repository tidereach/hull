# Spektralia

Local pre-cloud sensitivity gate. Normalizes and scans input for PII, credentials, and internal identifiers before any cloud LLM call; classifies residual risk locally via Ollama; blocks or passes the sanitized payload.

**Authoritative design spec:** [`docs/SPEC.md`](docs/SPEC.md) — read this before touching any code. [`docs/RATIONALE.md`](docs/RATIONALE.md) has the full design arguments. Open bugs and roadmap: [GitHub Issues](https://github.com/dormant-warlock/spektralia/issues). (`docs/PLAN.md` is retiring — see #133.) [`docs/ENDPOINT_STACK.md`](docs/ENDPOINT_STACK.md) shows how Spektralia composes with a sandbox (Fence) and a Falco policy layer (Prempti) into a layered endpoint stack; [`docs/SANDBOX_ALTERNATIVES.md`](docs/SANDBOX_ALTERNATIVES.md) compares Fence, navikt/cplt, and cplt-sndbx (preferred v1 backend, lives in `infra/sandbox/`). [`docs/TEST.md`](docs/TEST.md) is a step-by-step verification guide with expected test counts.

---

## Architecture

```
input
  │
  ▼  normalize (NFKC + strip zero-width/bidi/homoglyphs)
  ▼  scan      (regex + Luhn/MOD-11 validators + entropy + decoded payloads)
  ▼  sanitize  (random-suffix typed tokens; no public restore())
  ▼  classify  (Ollama, format=json, two-framing consensus, fail-closed)
  ▼  gate      (rule_hit OR classifier_high → block; else pass)
  │
  ▼ sanitized payload → cloud LLM call
```

Every action produces a hash-chained audit event. A canary corpus runs at startup and on a schedule; drift auto-freezes the gate.

---

## File layout

```
src/spektralia/
  __init__.py          gate, gate_sync, SensitiveDataError, GateResult, Settings
  config.py            Settings; precedence: kwargs > env > toml > defaults
  patterns.py          Pattern(label, regex, validator, priority)
  normalize.py         NFKC, strip obfuscation chars, homoglyph fold
  scanner.py           Detection dataclass, scan(), span dedupe
  entropy.py           Shannon entropy, token-boundary, allowlist
  decode.py            base64/hex/gzip unwrap + re-scan
  memory_safety.py     Secret(bytearray), zeroize, PR_SET_DUMPABLE
  sanitizer.py         random-suffix tokens, private _restore
  classifier.py        Ollama format=json, two framings, fast mode
  ollama_trust.py      UDS preferred; TCP with PID/exe pin fallback
  sandbox.py           execution-plane sandbox preflight (fence/cplt/cplt-sndbx); called by check-sandbox
  sessions/
    __init__.py        package root
    writer.py          best-effort JSONL turn writer to session-streams volume (Airlock substrate)
  cache.py             LRU keyed on sha256(sanitized_text + config_hash + pattern_hash + model_digest + prompt_hash)
  canary.py            corpus self-test, drift → auto-freeze
  integrity.py         pattern hash, model digest, dep lockfile check
  anomaly.py           rolling counters, auto-freeze, freeze file
  heartbeat.py         periodic audit emission
  audit.py             hash-chained, persistent, sink abstraction
  gate.py              orchestration, soft mode, --explain
  errors.py            SensitiveDataError
  cli.py               versioned subcommands

scripts/
  latency_bench.py     per-hook p95 latency benchmark (mocks Ollama with respx)
  redos_fuzz.py        adversarial ReDoS input fuzz; used by nightly redos-fuzz.yml CI

docs/
  SPEC.md              authoritative design spec
  PLAN.md              retiring — see issue #133; content migrating to RATIONALE.md, SPEC.md, and GitHub Issues
  RATIONALE.md         full design arguments
  ENDPOINT_STACK.md    how Spektralia composes with Fence + Prempti into a layered endpoint stack
  SANDBOX_ALTERNATIVES.md  Fence vs navikt/cplt vs cplt-sndbx comparison; cplt-sndbx is the v1 preferred backend
  TEST.md              step-by-step verification guide with expected test counts
  COMPLIANCE.md        GDPR/Datatilsynet/PCI-DSS/HIPAA/OWASP ASI Top 10 coverage
  THREATS.md           threat model — in-scope, out-of-scope, what gate does NOT detect

infra/sandbox/
  Containerfile        multi-stage image; ARG AGENT_CLI=copilot|claude|none; installs bwrap + spektralia
  docker-compose.yml   hardened stack: read_only rootfs, tmpfs, repos :ro, session-streams named volume
  setup.sh             auto-detects HOST_UID/GID → writes .env; run once before build
  start.sh             podman-compose run --rm agent
  .env.example         AGENT_CLI, HOST_UID/GID, WORKSPACE_DIR, REPO_PATHS, SESSION_STREAMS_VOLUME
  proxy/
    squid.conf         egress allowlist; CONNECT-only; blocks known exfiltration domains
    allowed-domains.txt  GitHub/Copilot/Anthropic/npm/PyPI + host.containers.internal:11434
    blocked-domains.txt  webhooks, paste sites, tunnels, IP recon (from LOTS + NAV cplt)
  landlock/
    agent.policy       declarative R/W policy (ro/rw/tmpfs per path); entrypoint.sh source of truth
    entrypoint.sh      bwrap wrapper enforcing agent.policy; falls back without bwrap (#139 = Landlock LSM follow-up)

integrations/claude/
  hooks/
    session_start.py     verify-integrity + self-test + hook-check
    user_prompt_submit.py
    pre_tool_use.py      Task, Bash, Write, Edit + default-deny MCP
    post_tool_use.py     Read, Bash, Grep, Glob, MCP results
    stop.py
  settings.example.json

integrations/copilot/
  hooks/
    _common.py           shared helpers for copilot hook scripts
    session_start.py
    user_prompt_submit.py
    pre_tool_use.py
    post_tool_use.py
    stop.py
  spektralia.json        Copilot hook configuration
```

---

## Commands

```bash
# Install (dev)
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pre-commit install   # wire git hooks (ruff, black, mypy, end-of-file-fixer, check-yaml)

# Run tests (uv not installed; invoke venv directly)
.venv/bin/pytest -q
.venv/bin/pre-commit run --files <files>   # lint gate — run before committing touched files

# CLI
spektralia scan                   # stdin → sanitized stdout; exit 2 on block
spektralia scan --explain         # show which detectors ran and why
spektralia self-test              # run canary corpus against live classifier
spektralia verify-integrity       # print pattern/model/prompt hashes
spektralia verify-installed       # check pip hashes against requirements.lock
spektralia stats                  # rolling counters + freeze state
spektralia freeze / unfreeze
spektralia audit-verify <path>
spektralia audit-rotate --keep-days <N>   # prune old audit records; re-anchors chain
spektralia audit-purge --before YYYY-MM-DD # GDPR Right to Erasure; re-anchors chain
spektralia scan-config            # lint AGENTS.md / CLAUDE.md files for sensitive content
spektralia hook-check             # assert Claude Code hooks installed correctly
spektralia check-ollama           # ping configured Ollama endpoint
spektralia check-sandbox          # assert configured execution-plane sandbox (fence|cplt|cplt-sndbx) is present
                                  # cplt-sndbx: checks podman/docker on PATH + infra/sandbox config hash
                                  #   bypass: SPEKTRALIA_SANDBOX_OFFLINE=1

# SBOM / supply chain
make sbom    # regenerate SBOM.json from requirements.lock (reproducible; lockfile-based)
make verify  # verify-integrity + verify-installed
make test    # .venv/bin/pytest -q
make lock    # re-pin requirements.lock with hashes (uv pip compile --python-version 3.11 --generate-hashes)
```

---

## Key decisions (see spec §§ for full rationale)

- **Fail-closed default.** Classifier outage → block, not pass. Toggle via `SPEKTRALIA_FAIL_OPEN=1`.
- **No public `restore()`.** Tokens are one-way by default; restoration is a private, opt-in, whitelist-required, single-use API.
- **`rule_hit OR classifier_high` to block.** Neither layer can unilaterally pass; either can block.
- **Two-framing classifier consensus.** `max(framing1, framing2)` confidence; disagreement is its own audit event.
- **Ollama trust.** Prefer UDS with 0600 owner-check; TCP fallback pins PID + binary hash.
- **Canary corpus.** If the classifier starts returning wrong answers (backdoored model, drift), the gate auto-freezes.
- **Audit chain persists across restarts.** `~/.spektralia/audit.state` holds the last hash; new sessions anchor to it.
- **`PreToolUse(Task)` hook is required.** Without it, a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`.

---

## Dependencies

```
httpx>=0.27
regex          # ReDoS-safe patterns with per-call timeout
keyring        # optional: TOML HMAC verification
```

Dev: `pytest pytest-asyncio respx cyclonedx-bom pip-tools pytest-cov mypy black ruff pip-audit`

Toolchain (install separately — not pip packages): `uv` (for `make lock`), `pre-commit` (for git hooks)

Ollama: `ollama pull llama3.1:8b`

---

## Claude Code hook integration

Copy `integrations/claude/settings.example.json` into `.claude/settings.json`
(project) or `~/.claude/settings.json` (global); replace `/path/to/spektralia` with the repo root.

| Hook | Effect |
|------|--------|
| `UserPromptSubmit` | Scans + sanitizes user prompt; blocks or substitutes |
| `PreToolUse` | Blocks sensitive data in Task/Bash/Write/Edit args; default-deny MCP |
| `PostToolUse` | Scans tool output before it re-enters context |
| `SessionStart` | Runs `verify-integrity` + canary self-test + `hook-check` |
| `Stop` | Emits session-end audit event |

**`PreToolUse(Task)` is required** — without it a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`.

```bash
spektralia hook-check   # verify all hooks are wired correctly
```


---

## Gotchas

- **`infra/sandbox` — workspace bind-mount must be pre-created by the user (run `setup.sh` first).** The container runtime creates the directory as `root` if absent, blocking agent writes. If it's already root-owned: `sudo chown $USER:$USER infra/sandbox/workspace`.
- **`infra/sandbox` — preferred runtime is Podman rootless.** bwrap namespace isolation works in Podman rootless (user namespaces available); enable `userns_mode: "keep-id:..."` in `docker-compose.yml` for Podman.
- **`integrity.py` — pre-existing mypy/ruff issues (fixed in feat/cplt-sndbx-integration).** If they reappear after a rebase: `type: ignore[return-value]` → `type: ignore[no-any-return]`; `isinstance(exc, (A, B))` → `isinstance(exc, A | B)` (UP038).
- **Entropy allowlist is matched against the original *and* punctuation-stripped token.**
  `find_high_entropy` strips `/ \ : -` (and similar) before the entropy calc, but the file-path
  and UUID allowlist matchers anchor on those exact characters. The scan loop checks
  `_is_allowlisted(token) or _is_allowlisted(clean)` for this reason — checking only the stripped
  form silently disables file-path exemption for absolute paths (the `/` prefix is gone), which is
  the false positive fixed in #22. Any new allowlist matcher must tolerate being run on both forms.
  See SPEC §6 for the full table.

- **`gate()` raises, does not return, on hard block.** In strict mode (default), `gate()` raises
  `SensitiveDataError`. It only returns `GateResult(blocked=True)` in soft mode
  (`SPEKTRALIA_MODE=soft`). All callers must `try/except SensitiveDataError`.

- **TOML config requires `[spektralia]` section.** Top-level keys in `.spektralia.toml` or
  `~/.spektralia/config.toml` are silently ignored. All settings must be under `[spektralia]`.

- **macOS: 1 test skipped.** `test_pr_set_dumpable` tests a Linux-only syscall (`PR_SET_DUMPABLE`)
  and skips on macOS. Expected suite result on macOS: `1 skipped, 1 xfailed`.

- **`llama3.2:3b` produces classifier false positives.** Use `llama3.1:8b` (the default).
  `llama3.2:3b` returns `sensitive=True, confidence=1.0, categories=[]` for short benign text
  even with JSON schema constraints.

- **`spektralia hook-check` checks both global and project settings.**
  `~/.claude/settings.json` and `.claude/settings.json` (project root) are both scanned;
  hooks may live in either or both files.

- **SBOM is generated from `requirements.lock`, not the active environment.** `make sbom` runs
  `cyclonedx-py requirements --output-reproducible -o SBOM.json requirements.lock`. Never run
  `cyclonedx-py environment` for committed SBOMs — it captures dev extras and transitive deps that
  differ between machines.

- **`uv` is not a pip package — install it separately before running `make lock`.** `pip install uv`
  works, or use the official installer. `pip-compile` (pip-tools) does not support `--python-version`
  in v7.x, so the lock target uses `uv pip compile --python-version 3.11` to include conditional
  deps (e.g. `typing-extensions`) that only apply to Python < 3.13.

- **`recheck` is not on PyPI.** `pip install recheck` fails — no such package. The nightly `redos-fuzz.yml` CI
  workflow uses pure-Python timeout assertion instead: runs each pattern against adversarial input and asserts the
  `regex` module's 100 ms timeout guard fires (returns `REGEX_TIMEOUT`); hangs >500 ms mean the guard is broken.

- **Hook self-scan exclusion: Write/Edit on Spektralia source files are not scanned.**
  `integrations/claude/hooks/pre_tool_use.py` skips scanning any `file_path` that contains
  `/src/spektralia/` or `/integrations/claude/hooks/` as a path segment. Without this, editing
  `patterns.py` or a hook script triggers the very credential patterns those files define, producing
  false positives on the gate's own source. The exclusion is path-keyed only — content is not
  inspected, so adding a real secret to a source file would still evade the hook; that is an accepted
  trade-off. See `test_pre_tool_use_own_source_not_scanned` in `tests/test_hooks.py`.

---

## Documenting exclusions and tuning changes

Every time a detector exclusion or tuning knob changes, record it *immediately* in the same PR/commit — not in a follow-up ticket, not in a TODO. Undocumented changes are how the #22 regression happened: an allowlist invariant nobody wrote down broke silently when the strip logic shifted.

**What counts as an exclusion or tuning change:**

- Entropy allowlist matchers (`entropy.py`: `_UUID_RE`, `_GIT_SHA_RE`, `_BASE64_IMAGE_RE`, `_FILE_PATH_RE`, and any future additions) and the `_TOKEN_SPLIT` strip that feeds them.
- Entropy constants (`min_len`, `threshold` in `find_high_entropy`).
- Classifier knobs — confidence thresholds, two-framing consensus rule, fail-open/closed toggle.
- Pattern priorities and validators (`patterns.py`).
- Sanitizer token format, cache keying components, anomaly counters, canary corpus composition.

**What to record every time:**

1. *What* changed — the constant, pattern, or allowlist entry by name.
2. *Why* — the false positive / false negative / threat that motivated it, with a concrete example payload where applicable.
3. *Invariants* the change relies on (e.g. "this matcher must be run on both the original and punctuation-stripped token").
4. *Regression reference* — the GitHub issue or PR that prompted the change.

**Where to record it:**

- `docs/SPEC.md` — for anything that becomes part of the design contract (allowlist entries, thresholds, decision rules). See §6 for the model.
- `AGENTS.md` "Gotchas" — for invariants a future agent must not silently break.
- Commit message body — the *why*, not just *what*.
- GitHub Issues — file one for any carry-over, bug, or tracked item (PLAN.md is retiring, see #133).

---

## When to open a PR (vs. commit straight to main)

Default to a pull request. A direct commit to `main` is only acceptable when **all** of the following hold; if any trigger fires, open a PR instead.

Open a PR when:
- The work is tied to a GitHub issue (any change that closes or advances a tracked item).
- Tests are touched, or could plausibly be affected — new behavior, changed behavior, refactors of code that has tests, anything that warrants CI signal beyond lint.
- More than one file changes, **excluding** edits confined to `AGENTS.md`, `CLAUDE.md`, and `README.md` (multi-file doc-only edits to those three files may still go straight to `main`).

Direct commits to `main` are fine for: single-file fixes with no issue and no test surface (typos, comment tweaks, dead-link fixes), and doc-only edits across `AGENTS.md` / `CLAUDE.md` / `README.md`.

---

## Branch lifecycle

Branches accumulate fast and merged ones quietly cause problems — new commits land on top of stale `main`, follow-up work piles onto an already-merged branch and needs its own PR to untangle, and the branch list fills with dead refs. Keep the working set small.

**Before starting work on a new branch.** Sync `main` with origin first; never branch from a stale local `main`.

```bash
git checkout main
git fetch origin
git pull --ff-only origin main
git checkout -b <new-branch-name>
```

**When to switch working branches.** Start a new branch for every distinct piece of work — every issue, every PR. Do **not** pile follow-up changes onto a branch whose PR has already merged; the branch's job is done and any new commits on it will diverge from `main`. If new scope surfaces mid-flight, finish and merge the current branch first, then branch again from a freshly-pulled `main`.

**After a PR merges.** Delete the branch locally and on origin in the same step — don't leave it for "later".

```bash
git checkout main
git fetch --prune origin           # also drops remote-tracking refs for deleted branches
git pull --ff-only origin main
git branch -d <merged-branch>      # local
git push origin --delete <merged-branch>   # remote (skip if GitHub auto-deleted it)
```

If `git branch -d` refuses (says "not fully merged"), the branch was probably squash-merged; verify on GitHub that the PR is closed/merged, then use `git branch -D` to force-delete.

**Stale-branch sweep.** `git branch -a` should be short. If you notice merged branches still listed on origin, delete them — they are not someone's in-flight work.

---

## When to file an issue

When work surfaces something that won't be handled in the current task — a future-scope idea, a non-blocking defect in unrelated code, a follow-up to a landing change, or a doc/spec inconsistency that isn't on the critical path — **file a GitHub issue rather than editing `docs/PLAN.md` or leaving a TODO comment**. Spawn the `file-issue` subagent with a short brief (one paragraph + any relevant file or section reference); it handles deduplication, labeling, and milestone assignment. Do not batch-defer to PLAN.md; the issue tracker is the authoritative backlog.

Trigger conditions:
- A future-scope improvement or optimization surfaces during focused work
- A non-blocking bug or inconsistency is noticed in code not being touched
- A follow-up change is needed but doesn't belong in the current PR
- A doc or spec inconsistency is found that isn't on the critical path

---

## What this gate does NOT cover

- Contextual PII in prose (names, addresses — NER tracked in #44)
- Model outputs / assistant turns (gating prose response stream is the wrong surface)
- `/compact` summarization (happens above the API; start fresh sessions for sensitive work)
- Attachments in Claude Code prompts (refused by default; `--allow-attachments` to opt in)
