from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from config.ports import MAX_PREFIXLEN


@dataclass(frozen=True)
class TargetPlan:
    original: str
    hosts: list[str]
    is_network: bool


def parse_target(value: str, max_prefixlen: int = MAX_PREFIXLEN) -> TargetPlan:
    target = value.strip()
    if not target:
        raise ValueError("Veuillez saisir une adresse IPv4 ou une plage CIDR.")

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            if network.version != 4:
                raise ValueError("Seules les adresses IPv4 sont prises en charge.")
            if network.prefixlen < max_prefixlen:
                raise ValueError(f"Plage trop grande. La version actuelle limite les scans à /{max_prefixlen} ou plus petit par défaut.")
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts:
                hosts = [str(network.network_address)]
            return TargetPlan(target, hosts, True)

        address = ipaddress.ip_address(target)
        if address.version != 4:
            raise ValueError("Seules les adresses IPv4 sont prises en charge.")
        return TargetPlan(target, [str(address)], False)
    except ValueError as exc:
        if str(exc).startswith(("Veuillez", "Seules", "Plage")):
            raise
        raise ValueError("Cible invalide. Exemple attendu : 192.168.1.10 ou 192.168.1.0/24.") from exc


def parse_ip_list(value: str) -> TargetPlan:
    hosts: list[str] = []
    for token in value.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        plan = parse_target(token)
        if plan.is_network:
            raise ValueError("La liste d'adresses IP ne doit contenir que des IPv4 uniques.")
        hosts.extend(plan.hosts)
    if not hosts:
        raise ValueError("Veuillez saisir au moins une adresse IPv4.")
    return TargetPlan(value, sorted(set(hosts)), False)
