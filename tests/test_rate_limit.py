"""Login rate-limit / lockout behavior tests."""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.core.lockout import LoginLockout, login_lockout
from tests.conftest import api_login


class TestLoginLockout:
    def test_lockout_after_max_failed_attempts(self, client, regular_user):
        settings = get_settings()
        limit = settings.LOGIN_MAX_FAILED_ATTEMPTS

        for _ in range(limit):
            resp = client.post(
                "/auth/login", data={"username": "alice", "password": "Wrong-Pass123"}
            )
            assert resp.status_code == 401

        # Even the CORRECT password is now rejected with 429.
        resp = api_login(client, "alice")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert "attempt" in resp.json()["detail"].lower()

    def test_lockout_is_per_identifier(self, client, regular_user, other_user):
        limit = get_settings().LOGIN_MAX_FAILED_ATTEMPTS
        for _ in range(limit):
            client.post(
                "/auth/login", data={"username": "alice", "password": "Wrong-Pass123"}
            )

        # alice is locked out, but bob (different identifier) is unaffected.
        assert api_login(client, "alice").status_code == 429
        assert api_login(client, "bob").status_code == 200

    def test_identifier_normalization_case_insensitive(self, client, regular_user):
        limit = get_settings().LOGIN_MAX_FAILED_ATTEMPTS
        for _ in range(limit):
            client.post(
                "/auth/login", data={"username": "Alice", "password": "Wrong-Pass123"}
            )
        # The same identifier in lower case is also locked.
        assert api_login(client, "alice").status_code == 429

    def test_success_clears_failure_counter(self, client, regular_user):
        limit = get_settings().LOGIN_MAX_FAILED_ATTEMPTS
        for _ in range(limit - 1):
            client.post(
                "/auth/login", data={"username": "alice", "password": "Wrong-Pass123"}
            )
        # A successful login resets the counter; further single failures don't lock.
        assert api_login(client, "alice").status_code == 200
        client.post(
            "/auth/login", data={"username": "alice", "password": "Wrong-Pass123"}
        )
        assert api_login(client, "alice").status_code == 200


class TestLockoutUnit:
    def test_window_expiry_releases_lock(self, monkeypatch):
        lockout = LoginLockout()
        settings = get_settings()
        for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS):
            lockout.record_failure("carol")
        assert lockout.is_locked("carol")

        # Simulate the window having fully elapsed (window = 0 seconds).
        monkeypatch.setattr(
            "app.core.lockout.get_settings",
            lambda: type("S", (), {"LOGIN_MAX_FAILED_ATTEMPTS": 5, "LOGIN_LOCKOUT_WINDOW_SECONDS": 0}),
        )
        assert not lockout.is_locked("carol")

    def test_reset_clears_state(self):
        lockout = LoginLockout()
        for _ in range(10):
            lockout.record_failure("dave")
        lockout.reset()
        assert lockout.pending_failures("dave") == 0

    def test_shared_instance_is_reset_between_tests(self):
        # Guarantees cross-test isolation of the global lockout store.
        assert login_lockout.pending_failures("nobody") == 0
