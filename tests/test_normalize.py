from spektralia.normalize import normalize, whitespace_collapsed_shadow


def test_nfkc_applied():
    # Full-width A becomes ASCII A
    result = normalize("Ａlice@example.com")
    assert "Ａ" not in result.normalized
    assert "A" in result.normalized or "a" in result.normalized.lower()


def test_zero_width_stripped():
    # Zero-width space between characters
    text = "al​ice@example.com"
    result = normalize(text)
    assert "​" not in result.normalized
    assert any(r[2] == "ZERO_WIDTH" for r in result.removals)


def test_bidi_stripped():
    text = "hello‮world"  # RLO character
    result = normalize(text)
    assert "‮" not in result.normalized
    assert any(r[2] == "BIDI_OVERRIDE" for r in result.removals)


def test_homoglyph_fold_cyrillic():
    # Cyrillic 'а' (U+0430) folds to 'a'
    text = "аpi_key"  # starts with Cyrillic а
    result = normalize(text)
    assert result.normalized.startswith("api_key") or "api" in result.normalized


def test_offset_map_length():
    text = "hello​world"
    result = normalize(text)
    # offset_map length == len(filtered) == len(text) - 1 (zero-width removed)
    assert len(result.offset_map) == len(text) - 1


def test_whitespace_shadow():
    shadow, idx_map = whitespace_collapsed_shadow("4111 1111 1111 1111")
    assert shadow == "4111111111111111"
    assert len(idx_map) == 16
    # First char maps to index 0
    assert idx_map[0] == 0


def test_homoglyph_fold_greek():
    # Greek ο (omicron, U+03BF) folds to 'o'; Greek ρ (rho) folds to 'p'
    # Construct a string that uses Greek lookalikes
    text = "αpi_key"  # Greek α (U+03B1) → 'a'
    result = normalize(text)
    assert result.normalized[0] == "a"


def test_homoglyph_fold_cyrillic_api_key():
    # Cyrillic а, р, і lookalikes assembled into "api_key"-like string
    # Cyrillic а (U+0430) → a, Cyrillic р (U+0440) → p
    text = "аpi_key=secret123"  # starts with Cyrillic а
    result = normalize(text)
    assert result.normalized.startswith("api_key=secret123")


def test_nfkc_expanding_span_round_trip():
    """Offset map must be correct for NFKC-expanding codepoints."""
    from spektralia.normalize import normalize

    # ﬃ (U+FB03) expands to "ffi" under NFKC (1 char → 3 chars)
    # Place a secret after it: "ﬃ:secret" where "secret" starts at original index 2
    original = "ﬃ:secret"
    # After NFKC: "ffi:secret" (10 chars), original "secret" starts at norm index 4
    result = normalize(original)
    assert result.normalized == "ffi:secret"
    # The 's' of 'secret' is at normalized index 4; original index must be 2
    assert result.offset_map[4] == 2
    # The 'e' is at normalized index 5; original index must be 3
    assert result.offset_map[5] == 3
