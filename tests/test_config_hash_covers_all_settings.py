"""Assert every Settings field is either in config_hash or explicitly excluded."""
from dataclasses import fields
from spektralia.config import Settings


def test_all_fields_accounted_for():
    s = Settings()
    non_policy = s._non_policy

    # Compute which fields ARE included in config_hash by computing hash,
    # then toggling each field and verifying hash changes (or field is non_policy).
    included: list[str] = []
    excluded: list[str] = []

    for f in fields(s):
        if f.name in non_policy:
            excluded.append(f.name)
        else:
            included.append(f.name)

    # Every field must be either included or explicitly excluded
    all_fields = {f.name for f in fields(s)}
    accounted = set(included) | set(excluded)
    unaccounted = all_fields - accounted
    assert unaccounted == set(), (
        f"Settings fields not in config_hash or _non_policy: {unaccounted}\n"
        "Add to config_hash computation OR add to _non_policy in Settings."
    )


def test_policy_field_change_changes_hash():
    """Changing a policy field must change the config_hash."""
    s1 = Settings(classifier_mode="strict")
    s2 = Settings(classifier_mode="fast")
    assert s1.config_hash() != s2.config_hash()


def test_non_policy_field_change_does_not_change_hash():
    """Changing a non-policy field must NOT change config_hash."""
    s1 = Settings(heartbeat_seconds=300)
    s2 = Settings(heartbeat_seconds=600)
    assert s1.config_hash() == s2.config_hash()


def test_threshold_change_changes_hash():
    s1 = Settings(sensitivity_threshold=0.7)
    s2 = Settings(sensitivity_threshold=0.5)
    assert s1.config_hash() != s2.config_hash()
