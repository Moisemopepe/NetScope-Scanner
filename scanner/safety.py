from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from scanner.validation import parse_ip_list, parse_target


@dataclass(frozen=True)
class TargetSafety:
    host_count: int
    contains_public: bool
    contains_private: bool
    message: str


def evaluate_target(target: str) -> TargetSafety:
    plan = parse_ip_list(target) if "," in target or ";" in target else parse_target(target)
    addresses = [ipaddress.ip_address(host) for host in plan.hosts]
    contains_public = any(not _is_local_or_private(address) for address in addresses)
    contains_private = any(_is_local_or_private(address) for address in addresses)
    if contains_public:
        message = "La cible contient au moins une adresse publique. Vérifiez que vous avez une autorisation explicite."
    else:
        message = "Cible locale ou privée."
    return TargetSafety(len(addresses), contains_public, contains_private, message)


def enforce_target_policy(target: str, max_hosts: int = 256) -> TargetSafety:
    safety = evaluate_target(target)
    if safety.host_count > max_hosts:
        raise ValueError(f"Trop d'hôtes à analyser ({safety.host_count}). Limite actuelle : {max_hosts}. Réduisez la plage ou utilisez une liste ciblée.")
    return safety


def _is_local_or_private(address: ipaddress._BaseAddress) -> bool:
    return bool(address.is_private or address.is_loopback or address.is_link_local)
