from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

APP_VERSION = "2.4.6"


@dataclass(frozen=True)
class AppSettings:
    language: str = "fr"
    theme: str = "dark"
    max_workers: int = 96
    discovery_timeout: float = 0.35
    tcp_timeout: float = 0.6
    banner_timeout: float = 0.8
    retries: int = 2
    ui_refresh_ms: int = 140
    max_hosts: int = 256
    cve_cache_days: int = 7
    offline_mode: bool = False
    nmap_enabled: bool = False
    report_dir: str = ""
    history_retention_days: int = 365
    log_level: str = "INFO"


def settings_path() -> Path:
    return Path.home() / "NetScope Scanner" / "settings.json"


def default_report_dir() -> Path:
    return Path.home() / "NetScope Scanner" / "reports"


def load_settings(path: Path | None = None) -> AppSettings:
    resolved = path or settings_path()
    if not resolved.exists():
        settings = AppSettings(report_dir=str(default_report_dir()))
        save_settings(settings, resolved)
        return settings
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("settings root must be an object")
        merged = asdict(AppSettings(report_dir=str(default_report_dir()))) | _clean_settings(data)
        return AppSettings(**merged)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        fallback = AppSettings(report_dir=str(default_report_dir()))
        save_settings(fallback, resolved)
        return fallback


def save_settings(settings: AppSettings, path: Path | None = None) -> None:
    resolved = path or settings_path()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(asdict(settings), ensure_ascii=False, indent=2), encoding="utf-8")


def recommended_settings() -> AppSettings:
    return AppSettings(report_dir=str(default_report_dir()))


def validate_settings(settings: AppSettings) -> None:
    if settings.max_workers < 1 or settings.max_workers > 512:
        raise ValueError("Le nombre de workers doit être compris entre 1 et 512.")
    if settings.discovery_timeout <= 0 or settings.tcp_timeout <= 0 or settings.banner_timeout <= 0:
        raise ValueError("Les timeouts doivent être strictement positifs.")
    if settings.max_hosts < 1 or settings.max_hosts > 4096:
        raise ValueError("La limite d'hôtes doit être comprise entre 1 et 4096.")
    if settings.ui_refresh_ms < 50 or settings.ui_refresh_ms > 1000:
        raise ValueError("La fréquence UI doit être comprise entre 50 et 1000 ms.")
    if settings.cve_cache_days < 1 or settings.cve_cache_days > 365:
        raise ValueError("La durée du cache CVE doit être comprise entre 1 et 365 jours.")


def _clean_settings(data: dict[str, Any]) -> dict[str, Any]:
    allowed = set(asdict(AppSettings()).keys())
    return {key: value for key, value in data.items() if key in allowed}
