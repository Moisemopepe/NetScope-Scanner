from __future__ import annotations

import pytest

from scanner.safety import enforce_target_policy, evaluate_target


def test_private_target_policy() -> None:
    safety = enforce_target_policy("192.168.1.0/30", max_hosts=10)
    assert safety.host_count == 2
    assert not safety.contains_public


def test_public_target_is_flagged() -> None:
    safety = evaluate_target("8.8.8.8")
    assert safety.contains_public


def test_target_policy_rejects_too_many_hosts() -> None:
    with pytest.raises(ValueError, match="Trop d'hôtes"):
        enforce_target_policy("192.168.1.0/24", max_hosts=10)
