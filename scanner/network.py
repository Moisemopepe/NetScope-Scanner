from __future__ import annotations

import ipaddress
import socket
import subprocess  # nosec B404
import sys

from scanner.process import run_hidden


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return "Non disponible"


def get_mac_address(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
        if address.is_loopback or address.is_multicast or address.is_unspecified:
            return "Non disponible"
        if sys.platform.startswith("win"):
            completed = run_hidden(["arp", "-a", ip], capture_output=True, text=True, timeout=0.5, check=False)  # nosec B607
            for line in completed.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if part.count("-") == 5:
                            return part.upper().replace("-", ":")
        else:
            completed = run_hidden(["arp", "-n", ip], capture_output=True, text=True, timeout=0.5, check=False)  # nosec B607
            for line in completed.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if part.count(":") == 5:
                            return part.upper()
    except (OSError, subprocess.SubprocessError):
        return "Non disponible"
    return "Non disponible"
