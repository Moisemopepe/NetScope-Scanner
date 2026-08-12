from __future__ import annotations

import pytest

from scanner.validation import parse_ip_list, parse_target


def test_accepts_single_ipv4() -> None:
    plan = parse_target("192.168.1.10")
    assert plan.hosts == ["192.168.1.10"]
    assert not plan.is_network


def test_accepts_cidr_24() -> None:
    plan = parse_target("192.168.1.0/30")
    assert plan.hosts == ["192.168.1.1", "192.168.1.2"]
    assert plan.is_network


def test_rejects_too_large_network() -> None:
    with pytest.raises(ValueError, match="Plage trop grande"):
        parse_target("192.168.0.0/16")


def test_rejects_invalid_target() -> None:
    with pytest.raises(ValueError, match="Cible invalide"):
        parse_target("not-an-ip")


def test_accepts_ip_list() -> None:
    plan = parse_ip_list("192.168.1.10, 192.168.1.11")
    assert plan.hosts == ["192.168.1.10", "192.168.1.11"]


def test_rejects_network_inside_ip_list() -> None:
    with pytest.raises(ValueError):
        parse_ip_list("192.168.1.0/30")
