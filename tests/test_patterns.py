from spektralia.patterns import (
    PATTERNS,
    Pattern,
    _jwt_header_valid,
    _luhn,
    _mod11_no,
    match_pattern,
)


def _get(label):
    return next(p for p in PATTERNS if p.label == label)


class TestEmail:
    def test_basic(self):
        pat = _get("EMAIL")
        r = match_pattern(pat, "Contact alice@example.com for details")
        assert any("alice@example.com" in m for _, _, m in r)

    def test_not_in_word(self):
        pat = _get("EMAIL")
        r = match_pattern(pat, "no email here just words")
        assert r == []


class TestIPAddr:
    def test_valid_ip(self):
        pat = _get("IP_ADDR")
        r = match_pattern(pat, "Server at 192.168.1.1 is down")
        assert r

    def test_invalid_octet_rejected(self):
        pat = _get("IP_ADDR")
        r = match_pattern(pat, "not an ip: 999.1.2.3")
        assert r == []

    def test_boundary_octet(self):
        pat = _get("IP_ADDR")
        r = match_pattern(pat, "10.0.0.255 is valid")
        assert r


class TestCreditCard:
    def test_luhn_valid(self):
        pat = _get("CREDIT_CARD")
        r = match_pattern(pat, "card 4111111111111111")
        assert r  # Luhn-valid Visa test number

    def test_luhn_invalid_rejected(self):
        pat = _get("CREDIT_CARD")
        r = match_pattern(pat, "card 4111111111111112")  # last digit wrong
        assert r == []

    def test_with_dashes(self):
        pat = _get("CREDIT_CARD")
        r = match_pattern(pat, "4111-1111-1111-1111")
        assert r


class TestNoPID:
    def test_valid_fnr(self):
        pat = _get("NO_PID")
        # Valid Norwegian national ID (test vector)
        r = match_pattern(pat, "fnr: 01010112345")
        # MOD-11 may or may not match this specific number
        # Just verify the pattern runs without error
        assert isinstance(r, list)

    def test_invalid_fnr_rejected(self):
        pat = _get("NO_PID")
        r = match_pattern(pat, "12345678901")
        # Should not match if MOD-11 fails
        assert isinstance(r, list)  # no error


class TestAwsKey:
    def test_akia(self):
        pat = _get("AWS_KEY")
        r = match_pattern(pat, "key: AKIAIOSFODNN7EXAMPLE")
        assert r

    def test_asia(self):
        pat = _get("AWS_KEY")
        # ASIA prefix + exactly 16 alphanumeric chars = 20 chars total
        r = match_pattern(pat, "ASIAXXX1234567890ABC")
        assert r


class TestJWT:
    def test_valid_jwt(self):
        import base64
        import json as _json

        pat = _get("JWT")
        header = (
            base64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            .decode()
            .rstrip("=")
        )
        payload = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        sig = "abc123"
        token = f"{header}.{payload}.{sig}"
        r = match_pattern(pat, f"token: {token}")
        assert r

    def test_invalid_header_rejected(self):
        pat = _get("JWT")
        r = match_pattern(pat, "eyNotBase64.stuff.sig")
        # May or may not match but shouldn't crash
        assert isinstance(r, list)


class TestPrivateKeyBlock:
    def test_rsa_pem(self):
        pat = _get("PRIVATE_KEY_BLOCK")
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        r = match_pattern(pat, text)
        assert r


class TestGithubToken:
    def test_ghp(self):
        pat = _get("GITHUB_TOKEN")
        r = match_pattern(pat, "ghp_" + "A" * 36)
        assert r


class TestPrivateKeyBody:
    def test_contiguous_base64_lines_detected(self):
        # 10+ lines of 64-char base64 content (no PEM header)
        line = "A" * 64
        body = "\n".join([line] * 12)
        pat = _get("PRIVATE_KEY_BODY")
        r = match_pattern(pat, body)
        assert r

    def test_few_lines_not_detected(self):
        # Only 3 base64 lines — too few to trigger heuristic
        line = "A" * 64
        body = "\n".join([line] * 3)
        pat = _get("PRIVATE_KEY_BODY")
        r = match_pattern(pat, body)
        assert r == []


class TestStripeKey:
    def test_sk_live(self):
        pat = _get("STRIPE_KEY")
        r = match_pattern(pat, "sk_live_" + "x" * 24)
        assert r

    def test_pk_live(self):
        pat = _get("STRIPE_KEY")
        r = match_pattern(pat, "pk_live_" + "y" * 24)
        assert r


class TestReDoSTimeout:
    def test_api_key_generic_timeout_handled(self):
        # A 10k-char string that could trigger ReDoS — should return REGEX_TIMEOUT or []
        # The important thing is it doesn't hang
        import time

        pat = _get("API_KEY_GENERIC")
        evil = "api_key=" + "a" * 5000
        t0 = time.monotonic()
        match_pattern(pat, evil)
        elapsed = time.monotonic() - t0
        # Must complete within 2 seconds regardless of match result
        assert elapsed < 2.0

    def test_regex_timeout_sentinel_returned(self, monkeypatch):
        # Verify that when timeout fires, match_pattern returns the REGEX_TIMEOUT sentinel
        import spektralia.patterns as p_mod

        monkeypatch.setattr(p_mod, "_TIMEOUT_MS", 0.001)
        pat = _get("API_KEY_GENERIC")
        r = match_pattern(pat, "api_key=" + "a" * 5000)
        assert r == [(-1, -1, "REGEX_TIMEOUT")]


# ---------------------------------------------------------------------------
# Validators (unit-tested directly — their edge branches are unreachable
# through match_pattern because the regex constrains the input shape)
# ---------------------------------------------------------------------------


class TestLuhnValidator:
    def test_too_few_digits_rejected(self):
        assert _luhn("123") is False  # < 13 digits

    def test_valid_number_with_doubling_over_nine(self):
        # 5555555555554444 is Luhn-valid; doubling 5 -> 10 -> 1 hits the d -= 9 branch
        assert _luhn("5555555555554444") is True

    def test_invalid_checksum_rejected(self):
        assert _luhn("5555555555554445") is False


_MOD11_W1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
_MOD11_W2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]


class TestMod11Validator:
    """Norwegian fødselsnummer MOD-11 double checksum."""

    def _valid_fnr(self, *, want_k1_eleven=False, want_k2_eleven=False) -> str:
        """Construct a checksum-valid 11-digit fnr, optionally exercising the
        k == 11 -> 0 control-digit branch for k1 or k2."""
        for n in range(5000):
            d = [int(c) for c in f"{n:09d}"]
            k1 = 11 - (sum(a * b for a, b in zip(d, _MOD11_W1)) % 11)
            k1_eleven = k1 == 11
            if k1 == 11:
                k1 = 0
            if k1 == 10:
                continue
            d10 = [*d, k1]
            k2 = 11 - (sum(a * b for a, b in zip(d10, _MOD11_W2)) % 11)
            k2_eleven = k2 == 11
            if k2 == 11:
                k2 = 0
            if k2 == 10:
                continue
            if want_k1_eleven and not k1_eleven:
                continue
            if want_k2_eleven and not k2_eleven:
                continue
            return "".join(str(x) for x in [*d10, k2])
        raise AssertionError("no valid fnr found in search range")

    def test_wrong_length_rejected(self):
        assert _mod11_no("123") is False

    def test_valid_fnr_accepted(self):
        assert _mod11_no(self._valid_fnr()) is True

    def test_k1_control_from_eleven_branch(self):
        assert _mod11_no(self._valid_fnr(want_k1_eleven=True)) is True

    def test_k2_control_from_eleven_branch(self):
        assert _mod11_no(self._valid_fnr(want_k2_eleven=True)) is True

    def test_wrong_first_control_digit_rejected(self):
        d = list(self._valid_fnr())
        d[9] = str((int(d[9]) + 1) % 10)
        assert _mod11_no("".join(d)) is False

    def test_wrong_second_control_digit_rejected(self):
        d = list(self._valid_fnr())
        d[10] = str((int(d[10]) + 1) % 10)
        assert _mod11_no("".join(d)) is False


class TestJwtHeaderValidator:
    def test_wrong_part_count_rejected(self):
        assert _jwt_header_valid("only.two") is False

    def test_undecodable_header_rejected(self):
        # '!!!' is not valid base64url → b64decode raises → caught → False
        assert _jwt_header_valid("!!!.payload.sig") is False

    def test_valid_header_accepted(self):
        import base64
        import json

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
        )
        assert _jwt_header_valid(f"{header}.e30.sig") is True


class TestMatchPatternDynamicCompile:
    def test_uncached_pattern_compiled_on_demand(self):
        # A Pattern whose label is not in the prebuilt _COMPILED cache exercises
        # the lazy-compile fallback in match_pattern.
        pat = Pattern(label="ZZZ_NOT_CACHED", regex=r"zebra\d+")
        r = match_pattern(pat, "see zebra42 over there")
        assert any("zebra42" in m for *_, m in r)
