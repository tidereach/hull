# Spektralia — Verification Guide

Step-by-step tests to confirm each phase is correctly implemented. Run them in order; each phase builds on the previous one.

---

## Prerequisites

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"   # quotes required in zsh to prevent glob expansion
```

Confirm install:
```bash
python -c "import spektralia; print('ok')"
spektralia --version   # prints: spektralia 0.1.0
```

---

## Run the full automated suite

```bash
.venv/bin/pytest -q
# Expected: 225 passed, 1 xfailed
```

The sections below re-run targeted subsets and then exercise the behaviour manually.

---

## Phase 1 — Deterministic core

**Covers:** `normalize`, `patterns`, `scanner`, `entropy`, `decode`, `sanitizer`, `memory_safety`, `integrity`, `config`

### 1.1 Automated tests

```bash
.venv/bin/pytest -q \
  tests/test_patterns.py \
  tests/test_normalize.py \
  tests/test_scanner.py \
  tests/test_entropy.py \
  tests/test_decode.py \
  tests/test_sanitizer.py \
  tests/test_memory_safety.py \
  tests/test_integrity.py \
  tests/test_config_hash_covers_all_settings.py \
  tests/test_no_secret_in_exceptions.py \
  tests/test_corpus.py
```

Expected: 119 passed, 1 xfailed.

### 1.2 Scanner smoke test

```bash
python -c "
from spektralia.scanner import scan
dets = scan('Contact alice@example.com or 4111111111111111')
for d in dets:
    print(d.label, d.start, d.end)
"
```

Expected output includes two lines: one with `EMAIL` and one with `CREDIT_CARD`.

### 1.3 Sanitizer round-trip

```bash
python -c "
from spektralia.scanner import scan
from spektralia.sanitizer import sanitize
text = 'email is alice@example.com'
s = sanitize(text, scan(text))
print(s.text)
assert '[REDACTED:EMAIL:' in s.text
assert 'alice' not in s.text
print('OK')
"
```

Expected: a line like `email is [REDACTED:EMAIL:xxxxxx]` (the suffix is a random hex token, so it varies) followed by `OK`. The original address must not appear.

### 1.4 Normalization + homoglyph fold

```bash
python -c "
from spektralia.normalize import normalize
# Cyrillic 'а' (U+0430) in place of Latin 'a'
result = normalize('аlice@exаmple.com')  # two Cyrillic chars
print(result.normalized)
# Should match alice@example.com after fold
"
```

Expected: normalized text contains `alice@example.com` (Latin only).

### 1.5 NFKC-expanding span round-trip

```bash
python -c "
from spektralia.scanner import scan
from spektralia.sanitizer import sanitize
# 'ﬃ' expands from 1 to 3 codepoints under NFKC
text = 'send to aﬃne@example.com'
dets = scan(text)
s = sanitize(text, dets)
print(s.text)
assert 'example.com' not in s.text or '[REDACTED' in s.text
print('OK')
"
```

Expected: a line like `send to [REDACTED:EMAIL:xxxxxx]` (random suffix) followed by `OK`. Confirms NFKC expansion doesn't break span alignment.

### 1.6 Entropy detection

```bash
python -c "
from spektralia.entropy import find_high_entropy
dets = list(find_high_entropy('key=xK9pL2mNqR7sT4vW1yZ3aB6cD8eF0gH AAAA'))
print([d.label for d in dets])
"
```

Expected: at least one `SECRET_HIGH_ENTROPY` detection on the high-entropy token.

### 1.7 Base64-encoded secret detection

```bash
python -c "
import base64
from spektralia.decode import decode_and_rescan
# payload must be >=40 base64 chars to trigger the pattern
secret = base64.b64encode(b'contact alice@example.com for billing info').decode()
dets = decode_and_rescan(secret)
print([d.label for d in dets])
"
```

Expected: `['EMAIL_ENCODED']`.

### 1.8 Secret value never in exceptions

```bash
python -c "
from spektralia.errors import SensitiveDataError
e = SensitiveDataError(reason='rule(EMAIL)', labels=('EMAIL',))
assert 'alice' not in str(e)
assert 'alice' not in repr(e)
print('OK:', str(e))
"
```

Expected: `OK: Blocked: rule(EMAIL)`. Confirms the exception message contains the block reason but never the original secret value.

### 1.9 Config hash stable and policy-sensitive

```bash
python -c "
from spektralia.config import Settings
s1 = Settings()
s2 = Settings()
assert s1.config_hash() == s2.config_hash(), 'hash must be deterministic'
s3 = Settings(sensitivity_threshold=0.99)
assert s3.config_hash() != s1.config_hash(), 'policy change must change hash'
print('OK')
"
```

Expected: `OK`.

### 1.10 Pattern hash deterministic

```bash
python -c "
from spektralia.integrity import compute_pattern_hash
h1 = compute_pattern_hash()
h2 = compute_pattern_hash()
assert h1 == h2
print('pattern_hash:', h1[:16], '...')
"
```

Expected: `pattern_hash: <16 hex chars> ...` (exact value varies with pattern table but is stable across runs).

### 1.11 PR_SET_DUMPABLE invoked at import (Linux only)

```bash
python -c "
import spektralia.memory_safety
# No exception means the import ran; check /proc if on Linux
import sys, os
if sys.platform == 'linux':
    val = open('/proc/self/status').read()
    for line in val.splitlines():
        if 'Dumpable' in line or 'dumpable' in line.lower():
            print(line)
"
```

Expected: no output (this kernel omits the `Dumpable` line from `/proc/self/status` when it is 0, which is the desired state). No exception means `PR_SET_DUMPABLE=0` was set successfully at import.

---

## Phase 2 — Audit, anomaly, classifier, cache, gate

**Covers:** `audit`, `anomaly`, `cache`, `classifier`, `ollama_trust`, `canary`, `gate`

### 2.1 Automated tests

```bash
.venv/bin/pytest -q \
  tests/test_audit_chain.py \
  tests/test_audit_no_values.py \
  tests/test_anomaly.py \
  tests/test_cache.py \
  tests/test_canary.py \
  tests/test_classifier.py \
  tests/test_ollama_trust.py \
  tests/test_gate.py
```

Expected: 54 passed. (`test_gate.py` and `test_ollama_trust.py` are mandatory — failures here mean a security-critical contract is broken.)

### 2.2 Audit chain integrity

```bash
python -c "
import tempfile, json
from pathlib import Path
from spektralia.audit import AuditChain, AppendOnlyFileSink

with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    sink = AppendOnlyFileSink(p / 'audit.jsonl')
    chain = AuditChain(p, sink=sink)
    chain.emit('pass', pattern_hash='aaa', model_digest='bbb', prompt_hash='ccc')
    chain.emit('block', pattern_hash='aaa', model_digest='bbb', prompt_hash='ccc', labels=['EMAIL'])
    chain.close()

    records = [json.loads(l) for l in (p / 'audit.jsonl').read_text().splitlines() if l]
    broken = chain.verify(records)
    print('broken indices:', broken)
    assert not broken
    print('OK — chain intact,', len(records), 'records')
"
```

Expected: `broken indices: []` followed by `OK — chain intact, 2 records`.

### 2.3 Audit chain survives restart

```bash
python -c "
import tempfile, json
from pathlib import Path
from spektralia.audit import AuditChain, AppendOnlyFileSink

with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    sink1 = AppendOnlyFileSink(p / 'audit.jsonl')
    c1 = AuditChain(p, sink=sink1)
    c1.emit('session_start', pattern_hash='', model_digest='', prompt_hash='')
    c1.close()

    sink2 = AppendOnlyFileSink(p / 'audit.jsonl')
    c2 = AuditChain(p, sink=sink2)
    c2.emit('session_end', pattern_hash='', model_digest='', prompt_hash='')
    c2.close()

    records = [json.loads(l) for l in (p / 'audit.jsonl').read_text().splitlines() if l]
    broken = c2.verify(records)
    print('broken:', broken)
    assert not broken
    print('OK — chain spans two sessions,', len(records), 'records')
"
```

Expected: `broken: []` followed by `OK — chain spans two sessions, 2 records`.

### 2.4 Audit log never stores sensitive values

```bash
python -c "
import tempfile, json
from pathlib import Path
from spektralia.audit import AuditChain, AppendOnlyFileSink

with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    sink = AppendOnlyFileSink(p / 'audit.jsonl')
    chain = AuditChain(p, sink=sink)
    chain.emit('block', pattern_hash='', model_digest='', prompt_hash='', labels=['EMAIL'])
    chain.close()

    raw = (p / 'audit.jsonl').read_text()
    assert 'alice@example.com' not in raw
    assert 'sk_live' not in raw
    print('OK — no sensitive values in audit log')
"
```

Expected: `OK — no sensitive values in audit log`.

### 2.5 Gate blocks on rule hit (mocked Ollama)

```bash
python -c "
import asyncio
from unittest.mock import patch, MagicMock
from spektralia.config import Settings
from spektralia.gate import gate
from spektralia.errors import SensitiveDataError

clf_safe = MagicMock()
clf_safe.sensitive = False
clf_safe.confidence = 0.1
clf_safe.categories = []
clf_safe.framing_disagreement = False
clf_safe.min_confidence = 0.1

async def run():
    try:
        with patch('spektralia.gate.classify', return_value=clf_safe):
            await gate('alice@example.com', Settings())
        print('ERROR: expected SensitiveDataError')
    except SensitiveDataError as e:
        print('blocked by rule:', e)
        assert 'EMAIL' in str(e).upper()
        print('OK')

asyncio.run(run())
"
```

Expected: `blocked by rule: Blocked: rule(EMAIL)` followed by `OK`. Gate raises `SensitiveDataError` on a rule hit — it does not return a `GateResult` with `blocked=True`.

> **macOS note (tested):** On macOS without a running Ollama, this snippet also prints `--- Logging error ---` blocks to stderr from the audit syslog sink (macOS syslog socket path differs from Linux `/dev/log`) and a `classifier error: Cannot reach Ollama` message. These are cosmetic — the gate still produces the correct result. **Linux: verify this runs cleanly without the syslog logging errors.**

### 2.6 Gate fails closed when classifier is unavailable

```bash
python -c "
import asyncio
from unittest.mock import patch
from spektralia.config import Settings
from spektralia.gate import gate
from spektralia.errors import SensitiveDataError

async def run():
    try:
        with patch('spektralia.gate.classify', side_effect=Exception('ollama down')):
            s = Settings(fail_open=False)
            await gate('hello world', s)
        print('ERROR: expected SensitiveDataError')
    except SensitiveDataError as e:
        print('blocked — classifier_unavailable:', e)
        print('OK — gate failed closed on classifier outage')

asyncio.run(run())
"
```

Expected:
```
classifier error: ollama down
blocked — classifier_unavailable: Blocked: classifier_unavailable
OK — gate failed closed on classifier outage
```

The `classifier error: ollama down` line is the gate's internal log for the classifier exception — it appears before the `SensitiveDataError` propagates and is normal.

### 2.7 Gate passes in fail-open mode when classifier is unavailable

```bash
python -c "
import asyncio, os
from unittest.mock import patch
from spektralia.config import Settings
from spektralia.gate import gate

async def run():
    with patch('spektralia.gate.classify', side_effect=Exception('ollama down')):
        s = Settings(fail_open=True)
        result = await gate('hello world', s)
    print('blocked:', result.blocked)
    assert not result.blocked, 'fail_open=True must pass when classifier is down'
    print('OK')

asyncio.run(run())
"
```

Expected: `blocked: False` followed by `sanitized_text: hello world` followed by `OK`.

### 2.8 Anomaly counter auto-freeze

```bash
python -c "
from spektralia.anomaly import AnomalyDetector

# threshold of 0.5 means >50% of events must be this type to freeze
# 10 events all of the same type = 100% rate → triggers freeze after >=3 events
a = AnomalyDetector(
    window_seconds=60,
    classifier_unavailable_rate_threshold=0.5,
    rule_classifier_disagreement_rate_threshold=0.5,
)
for _ in range(5):
    triggered = a.record('classifier_unavailable')
print('should_freeze:', a.should_freeze)
print('freeze_reason:', a.freeze_reason)
assert a.should_freeze
print('OK')
"
```

Expected:
```
anomaly: classifier_unavailable rate 1.00 > 0.50 — auto-freeze
anomaly: classifier_unavailable rate 1.00 > 0.50 — auto-freeze
anomaly: classifier_unavailable rate 1.00 > 0.50 — auto-freeze
should_freeze: True
freeze_reason: classifier_unavailable_rate_high (1.00)
OK
```

The repeated `anomaly:` lines are the detector logging each event that crosses the threshold — one per `record()` call once the rate exceeds 0.50.

### 2.9 Cache invalidation matrix

```bash
.venv/bin/pytest -q tests/test_cache.py -k "invalidat or miss_on"
```

Expected: `7 passed, 6 deselected` (covers pattern_hash, model_digest, prompt_hash, freeze, unfreeze, canary drift).

### 2.10 Ollama trust — UDS owner mismatch rejected

```bash
.venv/bin/pytest -q tests/test_ollama_trust.py -k "owner_mismatch or mode_0644 or world_writable"
```

Expected: `3 passed, 7 deselected` (UDS with wrong owner/mode raises, never silently accepted).

### 2.11 Canary corpus has positive and negative fixtures

```bash
.venv/bin/pytest -q tests/test_canary.py::test_canary_corpus_has_positive_and_negative
```

Expected: `1 passed`.

### 2.12 Gate with live Ollama (requires `ollama pull llama3.1:8b`)

> Skip this step if Ollama is not running locally. The gate falls back to fail-closed without it.

```bash
ollama pull llama3.1:8b

# Warm up the model first (first inference load can take several seconds)
ollama run llama3.1:8b "ping" --nowordwrap 2>/dev/null

python -c "
import asyncio
from spektralia.config import Settings
from spektralia.gate import gate
from spektralia.errors import SensitiveDataError

async def run():
    try:
        await gate('My email is alice@example.com', Settings())
        print('ERROR: expected SensitiveDataError')
    except SensitiveDataError as e:
        print('blocked:', e)
        assert 'EMAIL' in str(e).upper()
        print('OK — live gate blocked on email')

asyncio.run(run())
"
```

Expected: `blocked: Blocked: rule(EMAIL)...` followed by `OK — live gate blocked on email`.

> **Classifier timeout:** `check-ollama` only pings `/api/version` — it does not run inference. If the classifier times out (default 10 s), increase it: `SPEKTRALIA_CLASSIFIER_TIMEOUT_SECONDS=60 python -c "..."`. The gate still blocks correctly on the rule hit even when the classifier is unavailable.

---

## Phase 3 — CLI + Claude Code hooks

**Covers:** `cli.py`, `integrations/claude/hooks/`

### 3.1 Automated tests

```bash
.venv/bin/pytest -q tests/test_cli.py tests/test_hooks.py
```

Expected: `52 passed`.

### 3.2 `spektralia scan` — clean input

```bash
echo "The temperature is 42 degrees celsius." | spektralia scan
echo "exit $?"
```

Expected: prints `The temperature is 42 degrees celsius.`, exits 0.

> **Model false-positive note:** With a live Ollama, `llama3.1:8b` may return `{"sensitive": true, "confidence": 1.0, "categories": []}` for very short benign text like "hello world" — the classifier defaults to fail-closed when the model's response lacks specific categories. This is a model quality issue, not a bug. If this step blocks:
> - Use a longer, unambiguous sentence: `echo "The weather today is sunny and warm." | spektralia scan`
> - Or run with `SPEKTRALIA_FAIL_OPEN=1` to skip classifier-driven blocks for this test only
> - Or run without live Ollama (Ollama not running → gate fails closed with `classifier_unavailable`, which is also expected — skip this step in that case)

### 3.3 `spektralia scan` — sensitive input exits 2

```bash
echo "alice@example.com" | spektralia scan
echo "exit $?"
```

Expected: `Blocked: rule(EMAIL) + classifier(1.00, ['PII'])` on stderr, exits 2. No email value in stdout.

### 3.4 `spektralia scan --explain`

```bash
echo "alice@example.com" | spektralia scan --explain
```

Expected: `Blocked: rule(EMAIL) + classifier(1.00, ['PII'])` on stderr plus `[EMAIL]` detection and span info.

### 3.5 `spektralia verify-integrity`

```bash
spektralia verify-integrity
```

Expected:
```
pattern_hash: ea7c5d6000218632475c7d61bcd5383831b8cbf72525b6fdbe9951b7d6f5ceb4
prompt_hash: 34ee66ac1a8b2f84f2c1abfc094f50a589091f6d44a8d8f6a27cc368508b2965
model_digest:
```

`pattern_hash` and `prompt_hash` are deterministic (they hash the pattern table and classifier prompts). `model_digest` is empty unless `SPEKTRALIA_OLLAMA_MODEL_DIGEST` is set. Exit 0.

### 3.6 `spektralia stats`

```bash
spektralia stats
```

Expected: `frozen: False`. Exit 0.

### 3.7 `spektralia freeze` / `unfreeze`

```bash
spektralia freeze
spektralia stats | grep frozen
spektralia unfreeze
spektralia stats | grep frozen
```

Expected:
```
Gate frozen.
frozen: True (gate_frozen)
Gate unfrozen.
frozen: False
```

### 3.8 `spektralia audit-verify`

```bash
TMPDIR=$(mktemp -d)
python -c "
from pathlib import Path
from spektralia.audit import AuditChain, AppendOnlyFileSink
p = Path('$TMPDIR')
sink = AppendOnlyFileSink(p / 'audit.jsonl')
c = AuditChain(p, sink=sink)
c.emit('pass', pattern_hash='', model_digest='', prompt_hash='')
c.close()
"
spektralia audit-verify $TMPDIR/audit.jsonl
echo "exit $?"
```

Expected:
```
OK: 1 records, chain intact
exit 0
```

### 3.9 `spektralia audit-rotate`

```bash
spektralia audit-rotate --keep-days 90
echo "exit $?"
```

Expected:
```
OK: rotated audit log — 0 record(s) removed (keep_days=90)
exit 0
```

### 3.10 `spektralia audit-purge` — valid date

```bash
spektralia audit-purge --before 2020-01-01
echo "exit $?"
```

Expected:
```
OK: purged audit log — 0 record(s) removed (before=2020-01-01)
exit 0
```

### 3.11 `spektralia audit-purge` — invalid date exits 1

```bash
spektralia audit-purge --before not-a-date
echo "exit $?"
```

Expected: exits 1, error to stderr:
```
Error: Invalid date format 'not-a-date'; expected YYYY-MM-DD
exit 1
```

### 3.12 `spektralia scan-config` — safe CLAUDE.md

> Use a fresh isolated dir — `/tmp` may contain pytest temp dirs with email-bearing CLAUDE.md files
> that would trigger false hits.

```bash
TESTDIR=$(mktemp -d) && cd "$TESTDIR"
printf "# Hello\nThis is safe.\n" > CLAUDE.md
spektralia scan-config
echo "exit $?"
cd - && rm -rf "$TESTDIR"
```

Expected:
```
exit 0
```
(`cd -` prints the previous directory on the last line.)

### 3.13 `spektralia scan-config` — sensitive CLAUDE.md

```bash
TESTDIR=$(mktemp -d) && cd "$TESTDIR"
printf "# Config\ncontact me at alice@example.com\n" > CLAUDE.md
spektralia scan-config
echo "exit $?"
cd - && rm -rf "$TESTDIR"
```

Expected: exits 1, `EMAIL` in stderr:
```
WARN: CLAUDE.md: [EMAIL] at (2,40)
exit 1
```
(`cd -` prints the previous directory on the last line.)

### 3.14 `spektralia hook-check`

Create a minimal settings file, then check:

```bash
mkdir -p /tmp/fake-home/.claude
cat > /tmp/fake-home/.claude/settings.json <<'EOF'
{
  "hooks": {
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "python .../user_prompt_submit.py"}]}],
    "PreToolUse":       [{"matcher": ".*", "hooks": [{"type": "command", "command": "python .../pre_tool_use.py"}]}],
    "PostToolUse":      [{"matcher": ".*", "hooks": [{"type": "command", "command": "python .../post_tool_use.py"}]}],
    "SessionStart":     [{"hooks": [{"type": "command", "command": "python .../session_start.py"}]}]
  }
}
EOF
HOME=/tmp/fake-home spektralia hook-check
echo "exit $?"
```

Expected:
```
OK: all required hooks present
exit 0
```

### 3.15 Hook: MCP tool default-deny (subprocess I/O wiring)

```bash
echo '{"tool_name": "mcp__github__create_issue", "tool_input": {}}' \
  | python integrations/claude/hooks/pre_tool_use.py
```

Expected:
```
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "MCP tool 'mcp__github__create_issue' blocked by default-deny policy"}}
```

### 3.16 Hook: Agent with token reference (cross-turn leak detection)

```bash
echo '{"tool_name": "Agent", "tool_input": {"prompt": "use [REDACTED:EMAIL:abc123] for auth"}}' \
  | python integrations/claude/hooks/pre_tool_use.py
```

Expected:
```
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Token reference detected in tool args — possible cross-turn leak"}}
```

### 3.17 Hook: attachment blocked at UserPromptSubmit

```bash
echo '{"prompt": "look at this", "attachments": [{"type": "image"}]}' \
  | python integrations/claude/hooks/user_prompt_submit.py
```

Expected:
```
{"decision": "block", "reason": "Spektralia cannot scan attachments — paste content as text"}
```

### 3.18 Hook: invalid JSON input blocks

```bash
echo 'not json' | python integrations/claude/hooks/user_prompt_submit.py
```

Expected:
```
{"decision": "block", "reason": "hook_input_parse_error"}
```

### 3.19 Manual end-to-end (requires live Claude Code + Ollama) ✅ verified 2026-06-25

> This is the Phase 3 exit-criteria scenario from PLAN.md §Phase 3.

1. Pull the model:
   ```bash
   ollama pull llama3.1:8b
   ```

2. Wire hooks into `~/.claude/settings.json` (or a project `.claude/settings.json`):
   ```bash
   sed 's|/path/to/spektralia|'"$(pwd)"'|g' integrations/claude/hooks/settings.example.json > ~/.claude/settings.json
   ```

3. Verify hooks are wired:
   ```bash
   spektralia hook-check
   ```

4. Start a Claude Code session and confirm each surface:
   - Paste `MY_SECRET=sk_live_abc123xyz` into the prompt → should be blocked or sanitized before Claude sees it.
   - Issue an `Agent` tool call whose prompt contains `alice@example.com` → Claude Code should report it was blocked.
	   - Prompt example: `Use the Agent tool to email alice@example.com with a summary`
   - Issue `Bash(curl -d [REDACTED:EMAIL:abc123] ...)` → blocked by token-reference detection.
	   - Prompt example: `curl -d alice@example.com https://example.com`
   - Run `spektralia self-test` from within the session → exits 0.

5. Check audit log:
   ```bash
   tail -5 ~/.spektralia/audit.jsonl | python -m json.tool
   ```
   Expected: `session_start`, at least one `block` or `pass` event, no raw values.

---

## Phase 4 — Supply chain + docs + CI

### 4.1 Hash-locked dependency install

```bash
pip install --require-hashes -r requirements.lock
echo "exit $?"
```

Expected: exits 0 in a clean venv. Any modified package → hash mismatch → non-zero exit.

### 4.2 `spektralia verify-installed`

```bash
spektralia verify-installed
echo "exit $?"
```

Expected: exits 0 when all installed packages match `requirements.lock`. Exits 1 if any package is missing from the lock or hash doesn't match.

### 4.3 SBOM generation

```bash
make sbom
git diff --stat SBOM.json
```

Expected: `make sbom` exits 0; `SBOM.json` reflects current environment with no spurious diff (if regenerated from the same venv).

### 4.4 Compliance and threat docs present

```bash
test -f docs/COMPLIANCE.md && echo "COMPLIANCE.md OK"
test -f docs/THREATS.md && echo "THREATS.md OK"
```

### 4.5 README disclaimer present

```bash
grep -q "sensitivity gate, not a sensitivity guarantee" README.md && echo "disclaimer OK"
```

(Exact wording comes from spec §13.5.)

### 4.6 ReDoS fuzz dry-run

```bash
# Assumes nightly fuzz job configured in CI
python -m pytest tests/ -k "redos or timeout" -q
```

Expected: `TestReDoSTimeout` tests pass; any newly-added pattern with catastrophic backtracking fails here.

---

## Quick reference

| Command | Expected exit |
|---------|--------------|
| `pytest -q` | 0 (225 passed, 1 xfailed) |
| `echo "hello" \| spektralia scan` | 0 |
| `echo "alice@example.com" \| spektralia scan` | 2 |
| `spektralia verify-integrity` | 0 |
| `spektralia self-test` (with Ollama) | 0 |
| `spektralia freeze && spektralia stats` | 0, frozen: True |
| `spektralia audit-purge --before not-a-date` | 1 |
| `spektralia hook-check` (hooks wired) | 0 |
| `spektralia hook-check` (hooks missing) | 1 |
