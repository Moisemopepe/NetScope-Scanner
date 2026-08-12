from __future__ import annotations

import subprocess  # nosec B404
import sys
from collections.abc import Sequence
from typing import Any


def hidden_subprocess_kwargs() -> dict[str, Any]:
    if not sys.platform.startswith("win"):
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": startupinfo,
    }


def run_hidden(args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    check = kwargs.pop("check", False)
    return subprocess.run(args, **hidden_subprocess_kwargs(), check=check, **kwargs)  # nosec B603
