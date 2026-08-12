from __future__ import annotations

import subprocess

import pytest

from scanner.discovery import (
    NetworkDiscoverer,
    read_arp_table,
    reject_unreasonable_target,
    vendor_from_mac,
)
from scanner.local_network import choose_default_interface, cidr_from_address
from scanner.models import NetworkInterfaceInfo


def test_cidr_from_address() -> None:
    assert cidr_from_address("10.10.10.2", "255.255.255.0") == "10.10.10.0/24"


def test_choose_default_interface_from_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    interfaces = [
        NetworkInterfaceInfo("VPN", "172.16.0.2", "255.255.255.0", "172.16.0.0/24"),
        NetworkInterfaceInfo("Ethernet", "10.10.10.2", "255.255.255.0", "10.10.10.0/24"),
    ]
    monkeypatch.setattr("scanner.local_network.get_default_gateway", lambda: "10.10.10.1")
    assert choose_default_interface(interfaces).name == "Ethernet"


def test_read_arp_table_simulated(monkeypatch: pytest.MonkeyPatch) -> None:
    output = "  10.10.10.1           00-50-56-aa-bb-cc     dynamique\n"

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert read_arp_table()["10.10.10.1"] == "00:50:56:AA:BB:CC"


def test_vendor_from_mac() -> None:
    assert vendor_from_mac("00:50:56:AA:BB:CC") == "VMware"
    assert vendor_from_mac("AA:BB:CC:DD:EE:FF") == "Inconnu"


def test_tcp_reachable_even_if_icmp_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    discoverer = NetworkDiscoverer(tcp_ports=[80])
    monkeypatch.setattr("scanner.discovery.ping", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("scanner.discovery.tcp_probe", lambda ip, port, timeout: ip == "127.0.0.1" and port == 80)
    monkeypatch.setattr("scanner.discovery.read_arp_table", dict)
    monkeypatch.setattr("scanner.discovery.get_mac_address", lambda _ip: "Non disponible")
    monkeypatch.setattr("scanner.discovery.resolve_hostname", lambda _ip: "localhost")
    devices = discoverer.discover("127.0.0.1")
    assert devices[0].status == "Joignable"
    assert devices[0].discovery_method == "TCP"
    assert devices[0].open_ports == [80]


def test_reject_unreasonable_target() -> None:
    with pytest.raises(ValueError):
        reject_unreasonable_target("10.0.0.0/24", max_hosts=10)
