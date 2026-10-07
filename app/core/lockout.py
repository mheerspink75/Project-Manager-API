"""In-app login lockout (rate limiting keyed by credential identifier).

Deliberate design choice (documented per project requirements): the login
endpoint is rate limited *per identifier* (normalized username/email), which
the requirement explicitly asks for ("N failed attempts per identifier per
time window"). A generic IP-keyed limiter (e.g. slowapi) would not model that
semantics, so a small in-app implementation is used instead:

* thread-safe in-memory store of failed-attempt timestamps,
* sliding window (``LOGIN_LOCKOUT_WINDOW_SECONDS``),
* limit (``LOGIN_MAX_FAILED_ATTEMPTS``) configurable via settings,
* ``429`` responses while the window is active,
* a public ``reset()`` hook used by tests to guarantee isolation.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Iterable

from app.core.config import get_settings


class LoginLockout:
    """Sliding-window counter of failed login attempts per identifier."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = defaultdict(list)

    @staticmethod
    def normalize(identifier: str) -> str:
        return (identifier or "").strip().lower()

    def record_failure(self, identifier: str) -> None:
        key = self.normalize(identifier)
        now = time.monotonic()
        with self._lock:
            self._failures[key].append(now)
            self._prune(key, now)

    def is_locked(self, identifier: str) -> bool:
        settings = get_settings()
        key = self.normalize(identifier)
        now = time.monotonic()
        with self._lock:
            self._prune(key, now)
            return len(self._failures[key]) >= settings.LOGIN_MAX_FAILED_ATTEMPTS

    def clear(self, identifier: str) -> None:
        key = self.normalize(identifier)
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        """Drop all state (used by the test-suite for isolation)."""
        with self._lock:
            self._failures.clear()

    def pending_failures(self, identifier: str) -> int:
        key = self.normalize(identifier)
        with self._lock:
            self._prune(key, time.monotonic())
            return len(self._failures[key])

    def _prune(self, key: str, now: float) -> None:
        settings = get_settings()
        cutoff = now - settings.LOGIN_LOCKOUT_WINDOW_SECONDS
        timestamps: Iterable[float] = self._failures.get(key, ())
        self._failures[key] = [t for t in timestamps if t >= cutoff]


# Single process-wide instance; FastAPI endpoints share this object.
login_lockout = LoginLockout()
