from spektralia.entropy import _is_allowlisted, _shannon_entropy, find_high_entropy


def test_random_base64_flagged():
    # High-entropy random-looking string should trigger
    token = "tXj3K9mN2pQr7wVa8bCd4eF5gHiJ6kLo"  # 32 random-ish chars
    dets = find_high_entropy(f"key: {token}")
    assert dets, f"Expected high-entropy detection for token={token!r}"
    assert dets[0].label == "SECRET_HIGH_ENTROPY"


def test_uuid_not_flagged():
    dets = find_high_entropy("id: 550e8400-e29b-41d4-a716-446655440000")
    assert dets == []


def test_git_sha_not_flagged():
    dets = find_high_entropy("commit: 4b825dc642cb6eb9a060e54bf8d69288fbee4904")
    assert dets == []


def test_short_token_not_flagged():
    dets = find_high_entropy("x: abc123")  # too short
    assert dets == []


def test_lorem_not_flagged():
    dets = find_high_entropy("Lorem ipsum dolor sit amet consectetur")
    assert dets == []


def test_absolute_path_with_uuid_not_flagged():
    # Regression for #22: an absolute path containing a UUID (e.g. Copilot's
    # session-state plan file) must not trip SECRET_HIGH_ENTROPY. The leading
    # "/" is stripped before the entropy calc, so this only passes once the
    # allowlist is also checked against the original, unstripped token.
    path = "/home/user/.copilot/session-state/7bc3598a-1268-4f39-9043-aafb91193dd4/plan.md"
    assert find_high_entropy(path) == []


def test_absolute_path_not_flagged():
    # A long absolute path with no UUID must also pass.
    path = "/home/user/projects/spektralia/src/spektralia/some_long_module_name.py"
    assert find_high_entropy(path) == []


def test_random_token_in_path_position_still_flagged():
    # The path allowlist must not become a blanket escape: a genuine high-entropy
    # secret that doesn't start like a path is still flagged.
    dets = find_high_entropy("token=tXj3K9mN2pQr7wVa8bCd4eF5gHiJ6kLo")
    assert dets, "Expected high-entropy detection for a non-path random token"
    assert dets[0].label == "SECRET_HIGH_ENTROPY"


# ---------------------------------------------------------------------------
# Helpers — direct unit tests for the allowlist branches
# (find_high_entropy strips '-', ':', '/' for the entropy calc but now also
# checks the allowlist against the original token, so these are reachable
# end-to-end; the direct tests pin the matchers themselves)
# ---------------------------------------------------------------------------


def test_shannon_entropy_empty_is_zero():
    assert _shannon_entropy("") == 0.0


def test_is_allowlisted_uuid():
    assert _is_allowlisted("550e8400-e29b-41d4-a716-446655440000") is True


def test_is_allowlisted_git_sha():
    assert _is_allowlisted("4b825dc642cb6eb9a060e54bf8d69288fbee4904") is True


def test_is_allowlisted_base64_image():
    assert _is_allowlisted("data:image/png;base64,iVBORw0KGgo") is True


def test_is_allowlisted_file_paths():
    assert _is_allowlisted("/etc/secrets/key.pem") is True
    assert _is_allowlisted("~/secrets/key") is True
    assert _is_allowlisted("C:\\Users\\admin\\key") is True


def test_is_allowlisted_random_token_is_not():
    assert _is_allowlisted("tXj3K9mN2pQr7wVa8bCd") is False
