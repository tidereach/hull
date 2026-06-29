# airlock — L3 Execution Plane (sandbox + session-stream substrate)

> **Layer name:** airlock.
> **Plane:** Execution (L3).
> **Repo:** `tidereach/airlock`.
> **Status:** Migration spec; greenfield rebuild planned.

airlock is the execution-plane sandbox: the hardened container + egress proxy + per-path FS isolation that runs the agent process tree. It also owns the session-stream substrate — mounts a writable volume at the agent CLI's session-output path so the visibility plane (jettison) can read events directly. No Python source in v1; airlock ships container infrastructure.

cplt-sndbx is the v1 backend (decided in `docs/SANDBOX_ALTERNATIVES.md`).

Read [`MAIN.md`](MAIN.md) first; it sets the architecture, the decisions, and the execution order. This file is airlock's slice.

---

## Mission

airlock owns container-enforced execution and the substrate underneath the visibility plane. Concretely:

- **Hardened agent container**: `read_only: true` rootfs, all caps dropped, `pids_limit: 256` (operator override via `AGENT_PIDS_LIMIT`), tmpfs for cache / scratch, source repos `:ro`, only the active workspace `:rw`.
- **Squid egress allowlist proxy**: the only service in the compose stack with external network access. The agent's `HTTP_PROXY` / `HTTPS_PROXY` point here; any destination not in `allowed-domains.txt` is TCP-denied.
- **Per-path FS isolation**: `landrun` (Landlock LSM) where available, falling back to `bwrap` namespaces. Policy in `landlock/agent.policy`; entrypoint wraps the agent CLI.
- **Seccomp hardening profile**: blocks kernel-attack-vector syscalls.
- **Operator setup**: `setup.sh` auto-detects HOST_UID/GID → writes `.env`; `start.sh` brings up the stack; `sandbox-quickstart.sh` does a clean boot in <60s.
- **Session-stream substrate**: mounts a writable named volume — identifier `SESSION_STREAMS_VOLUME=session-streams` (Docker/Podman named volume) — at the in-container path `SESSION_DIR=/work/session-streams`. The agent CLI writes its JSONL session events into that path; jettison reads from the same volume.
- **v1 concurrency policy**: one active agent per compose stack. Parallel runs require separate stacks with distinct `SESSION_STREAMS_VOLUME` values; per-session volume scoping inside a single stack is v2 (`Open questions for v2`).
- **Per-agent-CLI build ARG**: `AGENT_CLI=copilot|claude|none` chooses which CLI is installed in the image.

airlock does **not** own: Python code (no library), audit log production (airlock originates no audit events directly; the Squid access log is written to a host-bound logfile that interlock's `SquidAccessReader` tails into the AuditChain — see Cross-layer contracts), control rule authoring (arbiter + operator), session-stream rule evaluation (jettison), hook composition order and OR-to-block semantics (layer0 interlock `governance/composition.md`; airlock participates in the chain by running inside it but does not define ordering).

---

## Scope decision history

References [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked):

- **Row 3 (4 sibling layer repos)**: airlock is import-decoupled from sieve today (`infra/sandbox/` only references `src/` at Containerfile build time). Post-split, the Containerfile pins a released sieve package rather than copying source.
- **Row 4 (open issues roll into specs)**: #138 (seccomp profile), #141 (proxy-running check) inform the v1 spec; their pre-migration commits are reviewed as design input for the greenfield rewrite, not applied as diffs. #139 (Landlock LSM), #140 (gVisor), #142 (arbiter engine sidecar) spec into airlock v2.
- **Row 6 (airlock owns substrate)**: `src/spektralia/sessions/writer.py` is **deleted, not migrated**. The agent CLI writes JSONL directly to a bind-mounted directory; the substrate is just a named volume + the right mount path; no Python writer required.
- **Row 8 (per-layer-file review)**: this file is reviewable standalone.

airlock is **Stage 4** in MAIN.md's execution order — requires sieve (Stage 3) release candidate for the Containerfile pin.

---

## Doc audit

| Doc | Disposition for airlock | Notes |
|---|---|---|
| `docs/SANDBOX_ALTERNATIVES.md` § cplt-sndbx (preferred v1 backend) | **Rewrite** | airlock's reason-to-exist; the v1 backend evaluation. |
| `docs/SANDBOX_ALTERNATIVES.md` § Comparison table | **Rewrite** | Rewrite as the trimmed v1 comparison; drop the historical comparison with Fence + navikt/cplt and keep cplt-sndbx as the canonical backend. The historical comparison reappears in a `HISTORY.md` appendix in the airlock repo, authored greenfield from the pre-migration text. |
| `docs/SANDBOX_ALTERNATIVES.md` § Residual gaps | **Rewrite** | In-project secrets stay readable; macOS Seatbelt deprecation; covert channels within allowed domains. |
| `docs/SANDBOX_ALTERNATIVES.md` § Wiring it into Spektralia's preflight | **Stay in interlock docs** | `check-sandbox` is interlock's CLI; airlock documents what the check inspects but the command lives in interlock. |
| `docs/ENDPOINT_STACK.md` § How cplt-sndbx wraps the agent | **Rewrite** | Container service map, the allowlist requirements (Ollama, session-streams writable, Prempti socket, workspace writable). |
| `docs/ENDPOINT_STACK.md` § Three planes of one endpoint | **Stay in hull (meta)** | Stack-level architecture; references airlock but not owned. |
| `docs/ENDPOINT_STACK.md` legacy Fence prose | **Reconcile** | The earlier drafts referenced Fence as canonical; reality is cplt-sndbx. Stage 1 (meta) reconciliation task; airlock docs assume cplt-sndbx is canonical. |
| `AGENTS.md` Gotchas — `infra/sandbox` workspace pre-create | **Rewrite** | Operator must pre-create; container runtime creates as root otherwise. |
| `AGENTS.md` Gotchas — preferred runtime is Podman rootless | **Rewrite** | `userns_mode: "keep-id:..."` required; bwrap namespace isolation works rootless in Podman. |
| `AGENTS.md` Gotchas — Squid 6 dstdomain ACL | **Rewrite** | FATAL invariant: bare and leading-dot variants for the same domain tree must not coexist. airlock ships a lint. |
| `AGENTS.md` Gotchas — `podman compose` vs `podman-compose` | **Rewrite** | The two look identical but differ in discovery. |
| `feat/cplt-sndbx-integration` branch commits (2918d3e, c861441, 5a12711, 0adef2f, 6bb6884) | **Inventory only** | The branch has unmerged changes to Containerfile, landlock/agent.policy, entrypoint.sh, ENDPOINT_STACK.md. Each commit's diff is reviewed as input to the greenfield rewrite; no diff is applied as a commit on the new repo. |
| `docs/PLAN.md` § 8 jettison | **Stay in jettison docs** | airlock provides the substrate; jettison documents what it consumes. |

**Doc reconciliation tasks**:

1. `docs/ENDPOINT_STACK.md` Fence prose is reconciled in Stage 1 (meta restructure); airlock's docs already assume cplt-sndbx is canonical.
2. The `infra/sandbox/AGENTS.md` (if it exists in the meta-repo post-Stage-1) references airlock by URL.

---

## Lessons learned

- **Workspace bind-mount must be pre-created** by the operator; otherwise the runtime creates it as root and the agent can't write. *Lesson:* the operator setup script must enforce this preflight. *v1:* `setup.sh` exits 1 with the message `workspace/ is root-owned; run: sudo chown -R $UID:$GID <workspace>` if it exists but is root-owned, or pre-creates with `$USER:$USER` ownership. No approval path — operator must resolve before re-running. `sandbox-quickstart.sh` re-asserts.

- **Podman rootless is preferred over Docker** for bwrap namespace isolation; user namespaces required. *Lesson:* the compose file should default to Podman rootless and `userns_mode: "keep-id:..."`. *v1:* compose ships Podman-rootless-first; docker compatibility documented but tested as a fallback only.

- **Squid 6 `dstdomain` ACL gotcha** — a bare entry covers domain + all subdomains; a leading-dot entry covers all subdomains including the bare. Both forms for the same domain tree are FATAL. *Lesson:* hand-maintained ACL lists drift silently. *v1:* `proxy/` ships with a lint script asserting no domain appears in both forms; pre-commit hook integration; CI gate.

- **Squid access log is a chain input, not a logfile-only artefact** — denied/allowed egress decisions belong on the AuditChain in v1, not just in a rotating proxy log. *Lesson:* a chain gap at the egress boundary is a v1 defect, and a tailing file reader is sufficient (no syslog sink needed). *v1:* the proxy container's only writable host mount is a **file-level bind** on `${PROXY_LOG_DIR}/access.log` (not a directory bind); Squid's `logfile_rotate` is disabled so the file is append-only per session and the reader's tail position is stable; interlock's `SquidAccessReader` (Stage 2) tails the file and appends one `egress_decision` envelope per line. Rotation/retention is v2. ACL lint and log-bind constraint are independent; both ship in `proxy/`.

- **`podman compose` (v2 plugin, space-separated) vs `podman-compose` (Python package)** look identical in compose files but discover differently. *Lesson:* the documented runtime invocation must be unambiguous. *v1:* README states `podman compose` (the plugin) is the supported invocation; `podman-compose` notes its incompatibilities.

- **bwrap fallback when bwrap is unavailable** (#138 / #139 territory). *Lesson:* the entrypoint must degrade gracefully and announce the degradation. *v1:* `landlock/entrypoint.sh` falls back without bwrap, printing a clear "Landlock unavailable; running with reduced isolation" stderr line; CI on a bwrap-less host asserts the fallback fires.

- **Workspace ownership** fragile across podman/docker (commits 0adef2f, 2918d3e, c861441 in `feat/cplt-sndbx-integration`). *Lesson:* per-runtime ownership semantics must be documented and tested separately. *v1:* `setup.sh` enumerates per-runtime steps; CI runs both Podman and Docker matrices.

- **Claude Code network domains** had to be carefully curated in `allowed-domains.txt` (commit 0adef2f). *Lesson:* allowlists are living documents; updates must be deliberate and auditable. *v1:* allow/deny lists ship as data with attribution comments; lint asserts no overlap with deny list; CI gate.

- **`AGENT_CLI=copilot|claude|none`** build ARG was a productive abstraction. *Lesson:* per-CLI variation belongs at build time, not at image time. *v1:* keep as-is; document each supported CLI's expected behaviour in the README.

- **`name-alchemist.{md,eval.md}` got committed to `infra/sandbox/workspace/`** — operator content leaked into the infra repo. *Lesson:* the `.gitignore` must aggressively cover any workspace path. *v1:* `.gitignore` covers `workspace/**`; CI asserts no untracked files appear under `workspace/` post-test.

- **Open issues #138 (seccomp), #141 (proxy-running check)** sit on the `feat/cplt-sndbx-integration` branch as recently-landed commits. *Lesson:* even recent work has to clear the greenfield-rewrite bar; nothing is copied as-is. *v1:* commits inspected as design input; the corresponding configuration is re-authored greenfield against the v1 spec, with monorepo-coupling stripped.

- **Open issues #139 (Landlock LSM), #140 (gVisor runsc), #142 (arbiter engine sidecar)** spec into airlock v2. *Lesson:* the v1 release deliberately leaves these as roadmap, not as gating items. *v2:* each issue becomes a tracked item in airlock's `ROADMAP.md`.

- **Session-stream substrate was a Python writer in L1** (`sessions/writer.py`). *Lesson:* the agent CLI already writes JSONL into a directory it controls; the substrate only needs the directory to be a writable volume jettison can mount-read. *v1:* airlock's `docker-compose.yml` declares a named volume mounted at `$SESSION_DIR` (default `/work/session-streams`); per-CLI configuration documented (which env var or config knob points the agent CLI's session output there); no Python in any layer.

---

## Reuse table

| Source (current) | Disposition | Notes |
|---|---|---|
| `infra/sandbox/Containerfile` | **Rewrite** | Rewrite per spec; the pre-migration multi-stage build is correct and guides the structure. As part of the rewrite, replace `COPY src/`/`pip install -e .` with `pip install tidereach-sieve==X.Y.Z` and keep the AGENT_CLI build ARG. |
| `infra/sandbox/docker-compose.yml` | **Rewrite** | Rewrite per spec; the pre-migration hardened service spec is correct and guides the design. As part of the rewrite, add a named-volume mount at the agent CLI's expected session-output path (`$SESSION_DIR`). |
| `infra/sandbox/proxy/squid.conf` | **Rewrite** | Rewrite per spec; the pre-migration configuration (cache TTL, access log destination) is the contract. As part of the rewrite, ship the ACL lint that verifies no Squid 6 `dstdomain` gotchas. |
| `infra/sandbox/proxy/allowed-domains.txt` | **Rewrite** | Re-authored greenfield with the pre-migration curated set as the source list; preserve attribution comments. Ship the overlap-free lint as part of the rewrite. |
| `infra/sandbox/proxy/blocked-domains.txt` | **Rewrite** | Curated from LOTS + NAV cplt; preserve attribution. |
| `infra/sandbox/landlock/agent.policy` | **Rewrite** | Declarative R/W per-path policy. |
| `infra/sandbox/landlock/entrypoint.sh` | **Rewrite** | Rewrite per spec; the pre-migration bwrap fallback path is invariant and guides the design. As part of the rewrite, CI on a bwrap-less host asserts the fallback fires. |
| `infra/sandbox/seccomp-agent.json` | **Rewrite** | #138 deliverable; the documented blocked syscalls are the contract. |
| `infra/sandbox/setup.sh` | **Rewrite** | Rewrite per spec; the pre-migration setup flow guides the design. As part of the rewrite, add the workspace pre-creation enforcement (lesson above). |
| `infra/sandbox/start.sh` | **Rewrite** | One-line `podman compose run --rm agent` wrapper. |
| `infra/sandbox/sandbox-quickstart.sh` | **Rewrite** | Rewrite per spec; the pre-migration smoke test guides the design. Re-test on a fresh host to confirm the <60s boot guarantee. |
| `infra/sandbox/.env.example` | **Rewrite** | Rewrite per spec; the pre-migration variable set (HOST_UID/GID, AGENT_CLI, WORKSPACE_DIR, REPO_PATHS, SESSION_STREAMS_VOLUME) guides the structure. As part of the rewrite, add `SESSION_DIR` (in-container mount path; distinct from SESSION_STREAMS_VOLUME), `PROXY_LOG_DIR` (host directory holding the Squid access logfile, file-bound into the proxy container), and `AGENT_PIDS_LIMIT` (default 256). |
| `infra/sandbox/.gitignore` | **Rewrite** | Rewrite per spec; the pre-migration ignore set guides the structure. As part of the rewrite, expand the `workspace/**` coverage to prevent name-alchemist-style leaks. |
| `infra/sandbox/workspace/name-alchemist.md` | **Drop** | Unrelated eval content. |
| `infra/sandbox/workspace/name-alchemist.eval.md` | **Drop** | Same. |
| `infra/sandbox/_podman` | **Drop** | Empty placeholder. |
| `infra/sandbox/.env` | **Drop** | Operator-local; should never have been committed. |

---

## v1 spec

### Deliverables

A runnable Podman/Docker Compose stack plus a fixed contract surface:

- `Containerfile` — multi-stage hardened image; `ARG AGENT_CLI=copilot|claude|none`; installs `bwrap`, the chosen agent CLI, and pinned `tidereach-sieve==X.Y.Z` from PyPI (no source copy).
- `docker-compose.yml` — two services:
  - `proxy` — Squid 6 egress allowlist; only service with external network access.
  - `agent` — `read_only: true`, caps dropped, `pids_limit: 256` (`AGENT_PIDS_LIMIT` env override), internal-only network; proxies through `proxy`.
- Named volumes: `agent-config`, `agent-outputs`, and the session-stream substrate identified by `SESSION_STREAMS_VOLUME=session-streams` (the Docker/Podman volume name used in compose `volumes:`) mounted at `SESSION_DIR=/work/session-streams` (the in-container path). Both variables appear in `.env.example` with this distinction stated inline.
- Proxy log host-bind: `${PROXY_LOG_DIR}/access.log` on the host is bind-mounted into the proxy container as the Squid access log destination. The proxy container has no other writable host mounts (rootfs `read_only`); compose declares the bind on the file (not the directory) so only the logfile is writable from the proxy.
- `proxy/squid.conf` + `proxy/allowed-domains.txt` + `proxy/blocked-domains.txt` — egress policy.
- `landlock/agent.policy` + `landlock/entrypoint.sh` — per-path FS isolation; bwrap fallback.
- `seccomp-agent.json` — seccomp profile blocking dangerous syscalls (#138).
- `setup.sh` — auto-detect HOST_UID/GID; write `.env`; create workspace dir with correct ownership. If `workspace/` exists but is root-owned, exit 1 with `workspace/ is root-owned; run: sudo chown -R $UID:$GID <workspace>` (no approval path — operator must resolve before re-running).
- `start.sh` — `podman compose run --rm agent`.
- `sandbox-quickstart.sh` — clean boot + smoke test in <60s.
- `.env.example` — every required env var with a sensible default: `HOST_UID`, `HOST_GID`, `AGENT_CLI`, `WORKSPACE_DIR`, `REPO_PATHS`, `SESSION_STREAMS_VOLUME` (the Docker/Podman named-volume identifier — default `session-streams`), `SESSION_DIR` (the in-container mount path — default `/work/session-streams`), `PROXY_LOG_DIR` (host directory holding `access.log` for interlock's `SquidAccessReader`), `AGENT_PIDS_LIMIT` (default `256`).

### Per-CLI configuration (substrate)

The agent CLI is configured to write its session output into `$SESSION_DIR`. airlock's docs enumerate two responsibilities per supported CLI: (1) **how the CLI is pointed at the substrate volume** (env var or config knob), and (2) **how the native transcript record is mapped into the `session-stream-jsonl/v1` schema** (which fields come from where; what fills `assistant_text` and `correlation_id`).

The mapping is performed by a per-CLI adapter inside interlock's policy module (`src/interlock/policy/adapters/<cli>.py`; see `layer0_interlock.md § Policy module` and `layer4_jettison.md § Module map`). The adapter — not airlock, not the agent CLI — is the entity that produces v1-shaped records; airlock's responsibility is to mount the substrate and ensure the native transcript lands on it. Locating the adapter in interlock keeps native-transcript-format knowledge co-located with the rule engine that consumes it (per `governance/layer-constraints.md`).

#### Substrate redirection

| CLI | How to point session output at `$SESSION_DIR` |
|---|---|
| Claude Code | **Primary (v1 canonical):** set `CLAUDE_TRANSCRIPT_DIR=$SESSION_DIR` in the agent service env — the CLI's native transcript output lands directly on the volume, enabling live `session-watch` in interlock's policy module. The Stop hook (if installed from hull meta-repo) emits a session-end audit event to interlock as a secondary signal but is not the primary stream producer. |
| Copilot CLI | Set `COPILOT_SESSION_DIR=$SESSION_DIR`; the CLI writes session JSON natively. Per-message events extracted by the Copilot adapter. |
| `none` (CLIs without a native session-output path) | Bind-mount `$SESSION_DIR` over the CLI's default state directory. |

#### Adapter mapping — `assistant_text`

The per-CLI adapter extracts the assistant turn text from the native transcript record at parse time. No env var or CLI flag is required; the wiring is purely a function of how each adapter reads its own native format:

| CLI | How `assistant_text` is populated |
|---|---|
| Claude Code | Adapter reads each JSONL line; for records where `type == "assistant"`, joins the text segments under `message.content[*].text` (matching the function `_extract_last_assistant_text` salvageable from the legacy `integrations/claude/hooks/stop.py`). Records of other types (`user`, `tool_use`, `tool_result`) emit `assistant_text = None`. |
| Copilot CLI | Adapter reads each session-JSON record; reads the `assistant.text` field (or equivalent per the Copilot transcript schema documented in the adapter). Non-assistant records emit `assistant_text = None`. |
| `none` | Adapter is not shipped for unknown CLIs; the operator supplies an adapter or accepts that `assistant_text = None`. |

#### Adapter mapping — `correlation_id`

`correlation_id` ties a `rule_hit` envelope back to the arbiter verdict that authorised the originating tool call. arbiter's engine receives the verdict request bearing a `context_id` (see interlock's `engine-ipc/v1` contract — the `POST /verdict {tool, args, session_id, context_id}` envelope); the verdict outcome is recorded by interlock's policy hook glue keyed by `(session_id, context_id)`. Two propagation paths into the v1 record are supported in v1:

1. **Native field** (preferred where the CLI permits it). If the agent CLI's transcript record schema includes a free-form metadata field that the per-call hook surface can populate (e.g., a "request id" passed through PreToolUse → CLI subprocess env → transcript), the adapter reads `correlation_id` directly from the record. For Claude Code v1, no such native field is guaranteed; the canonical path is (2).
2. **Sidecar join** (canonical v1). interlock's policy module maintains an in-process map `{(session_id, tool_call_seq) → context_id}` populated by the arbiter-verdict hook callback. The adapter, when producing each `SessionEvent` from a `tool_*` transcript record, looks up the matching entry by `(session_id, tool_call_seq)` and stamps `correlation_id`. If the lookup misses (e.g., a record produced before arbiter was consulted, or a non-tool transcript line), the adapter emits `correlation_id = None`. Non-tool records (pure `assistant`, `user`) emit `correlation_id = None`.

The substrate itself does **not** carry the verdict map; it carries only the agent CLI's native transcript. The map is a process-local artefact owned by interlock's policy module, scoped to the run.



### Cross-layer contracts honoured

- **Produces** the session-stream substrate consumed by jettison (named volume at `$SESSION_DIR`; schema governed by interlock's `session-stream-jsonl/v1` contract).
- **Audit-event posture**: airlock originates no audit events directly. Squid writes its access log to `${PROXY_LOG_DIR}/access.log` on the host (the proxy container's only writable host mount, bound on the file itself — not the directory). interlock owns a v1 component, `SquidAccessReader`, that tails this file, parses each line, and appends one audit envelope per line with `event=egress_decision` and labels `{domain, action: allow|deny, client, http_status}`. Domains/URLs are labels, not raw event args, per `audit-envelope/v1`. Squid's native `logfile_rotate` is disabled in v1; the file is append-only for the session (rotation/retention is v2). If `AuditChain.append()` raises inside `SquidAccessReader`, it logs to stderr and continues; the access line is preserved in the file but the chain envelope is lost (interlock cross-layer contracts document this). podman container logs remain outside the chain in v1. See `governance/audit-event-ownership.md`.
- **Bind-mounts** the arbiter engine socket (if arbiter + an engine are running on the host) at the path interlock's `engine-ipc` contract specifies (default `/run/arbiter-engine/hook.sock`).
- **Allows** `host.containers.internal:11434` in `allowed-domains.txt` so sieve's Ollama trust channel works.
- **Allowlists** every domain sieve / interlock / arbiter need to function (Anthropic API, GitHub API, npm registry, PyPI, etc.); deny list curates known exfiltration domains.
- **Publishes** the sandbox config-hash (compose + Containerfile + proxy lists + landlock policy + seccomp profile) as interlock's `check-sandbox` input.

### Verification

- `sandbox-quickstart.sh` boots the proxy + agent in <60s on the reference host (2-vCPU, 4GB RAM, SSD storage, Ubuntu 24.04 amd64 + arm64 (multi-arch baseline per Decision 17; both required for reproducible-build verification — see `MAIN.md § 12 Stage 4 airlock`), Podman rootless, base image pre-pulled). First clean-host timing is recorded as a Stage 4 sign-off artifact in `bench/stage4-baseline.txt` (one row per arch); subsequent regressions are measured against that baseline.
- **Egress test**: an allowed domain (Anthropic API) is reachable; a denied domain (paste.bin) returns TCP-RST. Within N seconds (N ≤ 2s) the blocked domain appears as an `egress_decision{action=deny}` envelope in the AuditChain (written by interlock's `SquidAccessReader` tailing the host-bound Squid access log), and `audit-verify` reports no chain breaks across the inserted envelopes.
- **bwrap fallback test**: remove bwrap from PATH; the entrypoint degrades gracefully and prints the documented "Landlock unavailable; running with reduced isolation" stderr line.
- **Seccomp test**: a documented dangerous syscall (e.g. `ptrace`) is blocked.
- **`tidereach interlock check-sandbox`** returns 0 against a healthy airlock image; returns 1 against a missing proxy container.
- **Substrate test**: a test agent run with `$SESSION_DIR` configured produces JSONL files in the volume; jettison can read them.
- **ACL lint**: `proxy/` lint passes (no domain in both bare and leading-dot form; no overlap between allow and deny).
- **CI matrix**: Podman rootless + Docker daemon both green.

---

## v2 spec

- **#139 — True Landlock LSM** via `landrun` or equivalent. Per-path R/W at the kernel level; supersedes bwrap fallback as the primary mechanism.
- **#140 — gVisor (`runsc`) runtime** as an optional alternative for syscall-level isolation. Higher cost; for high-assurance deployments.
- **#142 — arbiter engine sidecar packaging**. airlock ships a compose-stanza fragment that the operator can include to run the arbiter engine alongside the agent container.
- **macOS support story**: the v1 stack is Linux + Podman/Docker only. v2 documents Lima VM as the supported macOS path; tests don't run on macOS until v2.

---

## Out of scope

- **Python source** — airlock is infra-only.
- **Audit log production** — airlock originates no audit events directly. The Squid access log is a file artifact on a host-bound mount; interlock's `SquidAccessReader` ingests it into the AuditChain. podman container logs remain outside the chain in v1. See Cross-layer contracts.
- **Rule engine deployment** — arbiter + the operator pick the engine.
- **Content scanning** — sieve.
- **Behavioural detection / rule evaluation** — jettison.
- **Hook script bodies** — hull (meta-repo).
- **Cross-platform support beyond Linux + Podman/Docker** in v1 — documented gap.

---

## Open questions for v2

- **`landrun` vs custom Landlock-aware entrypoint** — which produces a more maintainable v2?
- **gVisor packaging for macOS hosts** — Lima VM is the likely answer; needs testing.
- **arbiter engine sidecar packaging** — operator pulls a fragment, or airlock ships variant compose files?
- **Per-agent-CLI substrate configuration** — should airlock ship a `configure-cli.sh` helper that knows each supported CLI's quirks?
- **Multi-tenant deployments**: today the substrate is per-process; v2 may need named volumes scoped per session-ID for parallel agent runs.
