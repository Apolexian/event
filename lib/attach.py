from __future__ import annotations

import logging
import time

import frida

log = logging.getLogger(__name__)

_TARGET_NAMES = [
    "UmamusumePrettyDerby.exe",
    "UmamusumePrettyDerby",
]
_KEYWORDS = ["uma", "musume", "derby", "cygames"]
MAX_WAIT_SECONDS = 120


def _candidates() -> list:
    try:
        procs = frida.get_local_device().enumerate_processes()
    except Exception as e:
        log.warning("enumerate_processes failed: %s", e)
        return []
    return sorted(
        [p for p in procs if any(kw in (p.name or "").lower() for kw in _KEYWORDS)],
        key=lambda p: (p.name or "").lower(),
    )


def attach(timeout: int = MAX_WAIT_SECONDS) -> frida.core.Session | None:
    deadline = time.monotonic() + timeout
    attempt = 0

    while time.monotonic() < deadline:
        attempt += 1

        for name in _TARGET_NAMES:
            try:
                session = frida.attach(name)
                log.info("Attached to %s", name)
                return session
            except Exception:
                pass

        for proc in _candidates():
            try:
                session = frida.attach(proc.pid)
                log.info("Attached to %s (pid %d)", proc.name, proc.pid)
                return session
            except Exception:
                pass

        if attempt == 1:
            log.info("Game not found, retrying every 3s (timeout %ds)...", timeout)

        time.sleep(3)

    log.error("Could not attach within %ds.", timeout)
    return None
