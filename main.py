from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config.settings import load_settings
from ui.app import NetScopeApp


def configure_logging() -> None:
    settings = load_settings()
    log_dir = Path.home() / "NetScope Scanner" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "netscope.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=[handler])


if __name__ == "__main__":
    configure_logging()
    app = NetScopeApp()
    app.mainloop()
