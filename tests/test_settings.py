from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import AppSettings, load_settings, save_settings, validate_settings


def test_settings_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = AppSettings(max_workers=12, max_hosts=128, report_dir=str(tmp_path))
    save_settings(settings, path)
    loaded = load_settings(path)
    assert loaded.max_workers == 12
    assert loaded.max_hosts == 128
    assert loaded.report_dir == str(tmp_path)


def test_settings_validation() -> None:
    validate_settings(AppSettings())
    with pytest.raises(ValueError):
        validate_settings(AppSettings(max_workers=0))
    with pytest.raises(ValueError):
        validate_settings(AppSettings(max_hosts=5000))
