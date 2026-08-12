from __future__ import annotations

import concurrent.futures
import re
import socket
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Callable, Iterable

from config.ports import get_port_info
from scanner.models import DiscoveredDevice
from scanner.network import get_mac_address, resolve_hostname
from scanner.validation import parse_ip_list, parse_target

DiscoveryCallback = Callable[[DiscoveredDevice], None]
DiscoveryProgressCallback = Callable[[int, int, str], None]

TCP_DISCOVERY_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389]
OUI_VENDOR_PREFIXES = {
    "00:1A:2B": "Fabricant de test",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
}


class NetworkDiscoverer:
    def __init__(self, timeout: float = 0.35, max_workers: int = 96, tcp_ports: Iterable[int] | None = None) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.tcp_ports = list(tcp_ports or TCP_DISCOVERY_PORTS)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def reset(self) -> None:
        self._stop_event.clear()

    @property
    def stopped(self) -> bool:
        return self._stop_event.is_set()

    def discover(
        self,
        target: str,
        ping_only: bool = False,
        include_unreachable: bool = False,
        on_device: DiscoveryCallback | None = None,
        on_progress: DiscoveryProgressCallback | None = None,
    ) -> list[DiscoveredDevice]:
        self.reset()
        plan = parse_ip_list(target) if "," in target or ";" in target else parse_target(target)
        found: list[DiscoveredDevice] = []
        arp_table = read_arp_table()
        total = len(plan.hosts)
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._discover_host, ip, ping_only, arp_table): ip for ip in plan.hosts if not self.stopped}
            for future in concurrent.futures.as_completed(futures):
                if self.stopped:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                ip = futures[future]
                completed += 1
                device = future.result()
                if include_unreachable or device.status == "Joignable":
                    found.append(device)
                    if on_device:
                        on_device(device)
                if on_progress:
                    on_progress(completed, total, ip)
        return sorted(found, key=lambda device: tuple(int(part) for part in device.ip.split(".")))

    def _discover_host(self, ip: str, ping_only: bool, arp_table: dict[str, str]) -> DiscoveredDevice:
        latency = ping(ip, self.timeout)
        mac = arp_table.get(ip) or get_mac_address(ip)
        methods: list[str] = []
        open_ports: list[int] = []
        services: list[str] = []
        if mac != "Non disponible":
            methods.append("ARP")
        if latency is not None:
            methods.append("ICMP")
        if not ping_only:
            for port in self.tcp_ports:
                if self.stopped:
                    break
                if tcp_probe(ip, port, self.timeout):
                    open_ports.append(port)
                    services.append(get_port_info(port).service)
                    methods.append("TCP")
        status = "Joignable" if methods else "Non joignable"
        return DiscoveredDevice(
            ip=ip,
            status=status,
            latency_ms=latency,
            hostname=resolve_hostname(ip),
            mac=mac,
            vendor=vendor_from_mac(mac),
            discovery_method="/".join(sorted(set(methods))),
            open_ports=open_ports,
            services=services,
            last_seen=time.strftime("%Y-%m-%d %H:%M:%S"),
            risk=_risk_from_ports(open_ports),
        )


def read_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        completed = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=2, check=False)  # nosec B603 B607
    except (OSError, subprocess.SubprocessError):
        return table
    for line in completed.stdout.splitlines():
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ip_match and mac_match:
            table[ip_match.group(1)] = mac_match.group(0).upper().replace("-", ":")
    return table


def ping(ip: str, timeout: float = 0.5) -> float | None:
    timeout_ms = max(100, int(timeout * 1000))
    args = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if sys.platform.startswith("win") else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        started = time.perf_counter()
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 1, check=False)  # nosec B603
        elapsed = (time.perf_counter() - started) * 1000
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r"(?:temps|time)[=<]?\s*(\d+(?:[.,]\d+)?)\s*ms", completed.stdout, re.IGNORECASE)
    if match:
        return float(match.group(1).replace(",", "."))
    return round(elapsed, 2)


def tcp_probe(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def vendor_from_mac(mac: str) -> str:
    if not mac or mac == "Non disponible":
        return "Inconnu"
    prefix = ":".join(mac.upper().replace("-", ":").split(":")[:3])
    return OUI_VENDOR_PREFIXES.get(prefix, "Inconnu")


def target_hosts_count(target: str) -> int:
    plan = parse_ip_list(target) if "," in target or ";" in target else parse_target(target)
    return len(plan.hosts)


def reject_unreasonable_target(target: str, max_hosts: int = 4096) -> None:
    count = target_hosts_count(target)
    if count > max_hosts:
        raise ValueError(f"Plage déraisonnablement grande ({count} hôtes). Limite : {max_hosts}.")


def _risk_from_ports(ports: list[int]) -> str:
    risks = {get_port_info(port).risk for port in ports}
    if "CRITIQUE" in risks:
        return "CRITIQUE"
    if "ÉLEVÉ" in risks:
        return "ÉLEVÉ"
    if "MOYEN" in risks:
        return "MOYEN"
    return "FAIBLE"
