"""Authentication endpoint tests: register, login, refresh, logout, token handling."""

from __future__ import annotations

import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from tests.conftest import api_login, auth_headers, make_user

REGISTRATION = {
    "email": "newuser@example.com",
    "username": "newuser",
    "password": "V3ry-G00d-Passw0rd",
}


class TestRegistration:
    def test_register_success(self, client):
        resp = client.post("/auth/register", json=REGISTRATION)
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "newuser@example.com"
        assert body["username"] == "newuser"
        assert body["role"] == "user"
        assert body["is_active"] is True
        assert "id" in body and "password" not in body and "hashed_password" not in body

    def test_register_duplicate_email_409(self, client):
        client.post("/auth/register", json=REGISTRATION)
        dup = dict(REGISTRATION, username="someone-else")
        resp = client.post("/auth/register", json=dup)
        assert resp.status_code == 409
        assert "email" in resp.json()["detail"].lower()

    def test_register_duplicate_username_409(self, client):
        client.post("/auth/register", json=REGISTRATION)
        dup = dict(REGISTRATION, email="other@example.com")
        resp = client.post("/auth/register", json=dup)
        assert resp.status_code == 409
        assert "username" in resp.json()["detail"].lower()

    def test_register_short_password_422(self, client):
        resp = client.post("/auth/register", json=dict(REGISTRATION, password="Ab1"))
        assert resp.status_code == 422

    def test_register_common_password_422(self, client):
        resp = client.post("/auth/register", json=dict(REGISTRATION, password="password123"))
        assert resp.status_code == 422

    def test_register_no_digit_password_422(self, client):
        resp = client.post(
            "/auth/register", json=dict(REGISTRATION, password="abcdefghijkl")
        )
        assert resp.status_code == 422

    def test_registered_user_can_login(self, client):
        assert client.post("/auth/register", json=REGISTRATION).status_code == 201
        resp = api_login(client, "newuser", "V3ry-G00d-Passw0rd")
        assert resp.status_code == 200
        assert "access_token" in resp.json()
        assert "refresh_token" in resp.json()


class TestLogin:
    def test_login_success_with_username(self, client, regular_user):
        resp = api_login(client, "alice")
        assert resp.status_code == 200
        tokens = resp.json()
        assert tokens["token_type"] == "bearer"

    def test_login_success_with_email(self, client, regular_user):
        resp = api_login(client, "alice@example.com")
        assert resp.status_code == 200

    def test_login_wrong_password_401(self, client, regular_user):
        resp = client.post(
            "/auth/login", data={"username": "alice", "password": "Wrong-Pass123"}
        )
        assert resp.status_code == 401

    def test_login_unknown_user_401(self, client):
        resp = client.post(
            "/auth/login", data={"username": "ghost", "password": "Whatever-123"}
        )
        assert resp.status_code == 401

    def test_login_inactive_user_403(self, client, inactive_user):
        resp = api_login(client, "dormant")
        assert resp.status_code == 403
        assert "inactive" in resp.json()["detail"].lower()

    def test_access_token_grants_me(self, client, regular_user):
        tokens = api_login(client, "alice").json()
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"


class TestTokenEdgeCases:
    """Defensive JWT handling in the auth dependency chain."""

    def test_refresh_type_token_rejected_as_bearer(self, client, regular_user):
        # A refresh token must not work as an access token.
        refresh = api_login(client, "alice").json()["refresh_token"]
        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {refresh}"}
        )
        assert resp.status_code == 401

    def test_token_with_non_integer_sub_rejected(self, client):
        import jwt as pyjwt

        from app.core.config import get_settings

        settings = get_settings()
        token = pyjwt.encode(
            {"sub": "not-an-id", "type": "access", "jti": "x"},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_token_for_nonexistent_user_rejected(self, client):
        import jwt as pyjwt

        from app.core.config import get_settings

        settings = get_settings()
        token = pyjwt.encode(
            {"sub": "999999", "type": "access", "jti": "x"},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_refresh_for_deleted_user_rejected(self, client, session, other_user):
        from app.core.security import create_refresh_token

        token = create_refresh_token(other_user.id, other_user.email)
        session.delete(other_user)
        session.commit()
        resp = client.post("/auth/refresh", json={"refresh_token": token})
        assert resp.status_code == 401

    def test_refresh_for_inactive_user_rejected(self, client, session, other_user):
        from app.core.security import create_refresh_token

        token = create_refresh_token(other_user.id, other_user.email)
        other_user.is_active = False
        session.commit()
        resp = client.post("/auth/refresh", json={"refresh_token": token})
        assert resp.status_code == 401


class TestTokenHandling:
    def test_missing_token_401(self, client):
        assert client.get("/users/me").status_code == 401

    def test_garbage_token_401(self, client):
        resp = client.get("/users/me", headers={"Authorization": "Bearer not-a-jwt"})
        assert resp.status_code == 401

    def test_expired_token_401(self, client):
        settings = get_settings()
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "1",
            "type": "access",
            "jti": "deadbeef",
            "exp": now - timedelta(minutes=1),
            "iat": now - timedelta(hours=2),
        }
        token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        resp = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_refresh_returns_new_pair(self, client, regular_user):
        first = api_login(client, "alice").json()
        resp = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert resp.status_code == 200
        second = resp.json()
        assert second["access_token"] != first["access_token"]
        assert second["refresh_token"] != first["refresh_token"]

    def test_refresh_rotates_old_refresh_token(self, client, regular_user):
        first = api_login(client, "alice").json()
        client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        # reuse of the rotated (revoked) refresh token must fail
        resp = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert resp.status_code == 401

    def test_refresh_rejects_access_token(self, client, regular_user):
        first = api_login(client, "alice").json()
        resp = client.post("/auth/refresh", json={"refresh_token": first["access_token"]})
        assert resp.status_code == 401

    def test_refresh_rejects_garbage(self, client, regular_user):
        resp = client.post("/auth/refresh", json={"refresh_token": "garbage"})
        assert resp.status_code == 401

    def test_logout_invalidates_refresh_token(self, client, regular_user):
        tokens = api_login(client, "alice").json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        resp = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}, headers=headers)
        assert resp.status_code == 204

        # the revoked refresh token can no longer be used
        resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert resp.status_code == 401

    def test_logout_is_idempotent(self, client, regular_user):
        tokens = api_login(client, "alice").json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        body = {"refresh_token": tokens["refresh_token"]}
        assert client.post("/auth/logout", json=body, headers=headers).status_code == 204
        assert client.post("/auth/logout", json=body, headers=headers).status_code == 204

    def test_logout_with_invalid_refresh_token_401(self, client, regular_user):
        tokens = api_login(client, "alice").json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        resp = client.post("/auth/logout", json={"refresh_token": "garbage"}, headers=headers)
        assert resp.status_code == 401

    def test_token_of_deactivated_account_rejected(self, client, session, regular_user):
        # Token minted while active; then the account is deactivated.
        tokens = api_login(client, "alice").json()
        regular_user.is_active = False
        session.commit()

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert resp.status_code == 403
        assert "inactive" in resp.json()["detail"].lower()
