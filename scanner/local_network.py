from __future__ import annotations

import ipaddress
import re
import socket
import subprocess  # nosec B404
import sys
from dataclasses import replace

import psutil

from scanner.models import NetworkInterfaceInfo
from scanner.process import run_hidden


def cidr_from_address(ipv4: str, netmask: str) -> str:
    return str(ipaddress.ip_network(f"{ipv4}/{netmask}", strict=False))


def get_default_gateway() -> str:
    try:
        if sys.platform.startswith("win"):
            completed = run_hidden(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True, timeout=2, check=False)  # nosec B607 B104
            for line in completed.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":  # nosec B104
                    return parts[2]
        else:
            completed = run_hidden(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2, check=False)  # nosec B607
            match = re.search(r"default via ([0-9.]+)", completed.stdout)
            if match:
                return match.group(1)
    except (OSError, subprocess.SubprocessError):
        return "Non disponible"
    return "Non disponible"


def active_interfaces() -> list[NetworkInterfaceInfo]:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    gateway = get_default_gateway()
    interfaces: list[NetworkInterfaceInfo] = []
    for name, addresses in addrs.items():
        is_up = stats.get(name).isup if name in stats else True
        if not is_up:
            continue
        ipv4 = ""
        netmask = ""
        mac = "Non disponible"
        for address in addresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                ipv4 = address.address
                netmask = address.netmask or ""
            elif _is_mac_family(address.family) and address.address:
                mac = address.address.upper().replace("-", ":")
        if ipv4 and netmask:
            interfaces.append(NetworkInterfaceInfo(name=name, ipv4=ipv4, netmask=netmask, cidr=cidr_from_address(ipv4, netmask), mac=mac, gateway=gateway, is_up=is_up))
    return interfaces


def choose_default_interface(interfaces: list[NetworkInterfaceInfo] | None = None) -> NetworkInterfaceInfo | None:
    items = interfaces or active_interfaces()
    if not items:
        return None
    gateway = get_default_gateway()
    if gateway != "Non disponible":
        for item in items:
            if ipaddress.ip_address(gateway) in ipaddress.ip_network(item.cidr, strict=False):
                return replace(item, gateway=gateway)
    return items[0]


def _is_mac_family(family: object) -> bool:
    name = getattr(family, "name", str(family))
    return name in {"AF_LINK", "AF_PACKET"} or "AF_LINK" in str(family) or "AF_PACKET" in str(family)
