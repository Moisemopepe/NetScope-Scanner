from __future__ import annotations

import pytest

from config.ports import get_port_info
from services.scan_profiles import parse_port_selection, ports_for_profile


def test_port_service_mapping() -> None:
    info = get_port_info(443)
    assert info.service == "HTTPS"
    assert info.risk == "FAIBLE"


def test_telnet_is_critical() -> None:
    assert get_port_info(23).risk == "CRITIQUE"


def test_custom_ports_are_validated() -> None:
    assert ports_for_profile("Personnalisé", "22, 8080") == [22, 8080]
    with pytest.raises(ValueError):
        ports_for_profile("Personnalisé", "70000")


def test_custom_port_ranges_are_supported() -> None:
    assert parse_port_selection("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        parse_port_selection("1024-1")
    with pytest.raises(ValueError):
        parse_port_selection("abc")
