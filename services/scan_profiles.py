from __future__ import annotations

from config.ports import FAST_PORTS, STANDARD_PORTS

FULL_PORTS = list(range(1, 65536))


def ports_for_profile(profile: str, custom_ports: str = "") -> list[int]:
    normalized = profile.lower()
    if normalized in {"rapide", "découverte rapide"}:
        return FAST_PORTS
    if normalized == "scan complet":
        return FULL_PORTS
    if normalized == "ping uniquement":
        return []
    if normalized == "personnalisé":
        return parse_port_selection(custom_ports)
    return STANDARD_PORTS


def parse_port_selection(custom_ports: str) -> list[int]:
    ports: set[int] = set()
    for token in custom_ports.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise ValueError("Les plages de ports doivent être croissantes.")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(token))
    if not ports:
        raise ValueError("Veuillez saisir au moins un port personnalisé.")
    return sorted(ports)


def _parse_port(value: str) -> int:
    if not value.strip().isdigit():
        raise ValueError("Les ports personnalisés doivent contenir uniquement des nombres et des plages.")
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("Les ports doivent être compris entre 1 et 65535.")
    return port
