"""User management tests: full authorization matrix + admin self-protection."""

from __future__ import annotations

from tests.conftest import auth_headers, make_user

PAYLOAD_USER = {
    "email": "carol@example.com",
    "username": "carol",
    "password": "S3cure-Passw0rd",
    "role": "user",
    "is_active": True,
}


class TestAuthorizationMatrix:
    """Anonymous / regular / admin / inactive against the user endpoints."""

    def test_anonymous_cannot_list_users(self, client):
        assert client.get("/users").status_code == 401

    def test_anonymous_cannot_read_user(self, client, regular_user):
        assert client.get(f"/users/{regular_user.id}").status_code == 401

    def test_anonymous_cannot_create_user(self, client):
        assert client.post("/users", json=PAYLOAD_USER).status_code == 401

    def test_regular_user_cannot_list_users(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.get("/users", headers=headers).status_code == 403

    def test_regular_user_cannot_read_user(self, client, regular_user, other_user):
        headers = auth_headers(client, regular_user)
        # 403 even though the target user exists (existence is not leaked).
        assert client.get(f"/users/{other_user.id}", headers=headers).status_code == 403

    def test_regular_user_cannot_read_missing_user(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        # 403 regardless of existence.
        assert client.get("/users/999999", headers=headers).status_code == 403

    def test_regular_user_cannot_create_user(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.post("/users", json=PAYLOAD_USER, headers=headers).status_code == 403

    def test_regular_user_cannot_update_user(self, client, regular_user, other_user):
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            f"/users/{other_user.id}", json={"is_active": False}, headers=headers
        )
        assert resp.status_code == 403

    def test_regular_user_cannot_delete_user(self, client, regular_user, other_user):
        headers = auth_headers(client, regular_user)
        resp = client.delete(f"/users/{other_user.id}", headers=headers)
        assert resp.status_code == 403

    def test_inactive_user_cannot_manage_users(self, client, inactive_user):
        # A validly-signed token for a deactivated account is rejected (403).
        from app.core.security import create_access_token

        token = create_access_token(inactive_user.id, inactive_user.email, "admin")
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/users", headers=headers).status_code == 403

    def test_admin_can_list_users(self, client, admin, regular_user):
        headers = auth_headers(client, admin)
        resp = client.get("/users", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        usernames = {item["username"] for item in body["items"]}
        assert "admin" in usernames and "alice" in usernames

    def test_admin_can_read_user(self, client, admin, regular_user):
        headers = auth_headers(client, admin)
        resp = client.get(f"/users/{regular_user.id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_admin_can_read_missing_user_404(self, client, admin):
        headers = auth_headers(client, admin)
        assert client.get("/users/999999", headers=headers).status_code == 404


class TestAdminUserCrud:
    def test_admin_create_user(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.post("/users", json=PAYLOAD_USER, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["username"] == "carol"

    def test_admin_create_user_admin_role(self, client, admin):
        headers = auth_headers(client, admin)
        payload = dict(PAYLOAD_USER, role="admin")
        resp = client.post("/users", json=payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["role"] == "admin"

    def test_admin_create_user_invalid_role_422(self, client, admin):
        headers = auth_headers(client, admin)
        payload = dict(PAYLOAD_USER, role="superuser")
        assert client.post("/users", json=payload, headers=headers).status_code == 422

    def test_admin_create_user_weak_password_422(self, client, admin):
        headers = auth_headers(client, admin)
        payload = dict(PAYLOAD_USER, password="weak")
        assert client.post("/users", json=payload, headers=headers).status_code == 422

    def test_admin_create_duplicate_email_409(self, client, admin, regular_user):
        headers = auth_headers(client, admin)
        payload = dict(PAYLOAD_USER, email="alice@example.com", username="carol")
        assert client.post("/users", json=payload, headers=headers).status_code == 409

    def test_admin_update_user(self, client, admin, other_user):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}",
            json={"role": "admin", "is_active": False},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"
        assert resp.json()["is_active"] is False

    def test_admin_update_user_password(self, client, admin, session, other_user):
        from app.core.security import verify_password

        headers = auth_headers(client, admin)
        new_password = "N3w-Passw0rd-Here"
        resp = client.patch(
            f"/users/{other_user.id}", json={"password": new_password}, headers=headers
        )
        assert resp.status_code == 200
        session.expire_all()
        assert verify_password(new_password, other_user.hashed_password)

    def test_admin_update_weak_password_422(self, client, admin, other_user):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}", json={"password": "password123"}, headers=headers
        )
        assert resp.status_code == 422

    def test_admin_delete_user(self, client, admin, session, other_user):
        headers = auth_headers(client, admin)
        victim_id = other_user.id
        assert client.delete(f"/users/{victim_id}", headers=headers).status_code == 204
        assert client.get(f"/users/{victim_id}", headers=headers).status_code == 404

    def test_admin_delete_missing_user_404(self, client, admin):
        headers = auth_headers(client, admin)
        assert client.delete("/users/999999", headers=headers).status_code == 404

    def test_admin_update_username_conflict_409(self, client, admin, regular_user, other_user):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}",
            json={"username": regular_user.username},
            headers=headers,
        )
        assert resp.status_code == 409
        assert "username" in resp.json()["detail"].lower()

    def test_admin_update_username_success(self, client, admin, other_user):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}", json={"username": "bobby"}, headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "bobby"


class TestAdminSelfProtection:
    """An admin cannot deactivate/demote/delete their own account."""

    def test_admin_cannot_deactivate_self(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{admin.id}", json={"is_active": False}, headers=headers
        )
        assert resp.status_code == 400
        assert "own account" in resp.json()["detail"]

    def test_admin_cannot_demote_self(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{admin.id}", json={"role": "user"}, headers=headers
        )
        assert resp.status_code == 400
        assert "own account" in resp.json()["detail"]

    def test_admin_cannot_deactivate_and_demote_self(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{admin.id}", json={"is_active": False, "role": "user"}, headers=headers
        )
        assert resp.status_code == 400

    def test_admin_cannot_delete_self(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.delete(f"/users/{admin.id}", headers=headers)
        assert resp.status_code == 400
        assert "own account" in resp.json()["detail"]
        # Account still exists and still admin.
        resp = client.get(f"/users/{admin.id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"

    def test_admin_can_update_own_nonprivileged_fields(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{admin.id}",
            json={"email": "admin-new@example.com"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "admin-new@example.com"
        assert resp.json()["role"] == "admin"

    def test_admin_can_keep_own_admin_role(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{admin.id}", json={"role": "admin"}, headers=headers
        )
        assert resp.status_code == 200


class TestMeEndpoint:
    def test_me_returns_current_user(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        resp = client.get("/users/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"
        assert "hashed_password" not in resp.json()

    def test_me_requires_auth(self, client):
        assert client.get("/users/me").status_code == 401

    def test_me_inactive_rejected(self, client, session, regular_user):
        # Token was minted while active; use it after deactivation.
        from app.core.security import create_access_token

        token = create_access_token(regular_user.id, regular_user.email, "user")
        regular_user.is_active = False
        session.commit()

        resp = client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    def test_me_update_profile(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            "/users/me",
            json={"username": "alice2", "password": "N3w-Passw0rd-Here"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice2"

    def test_me_cannot_change_role_or_active(self, client, regular_user, other_user):
        # Privileged fields are not part of UserSelfUpdate; even if a client
        # sends them, they must not be applied.
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            "/users/me",
            json={"role": "admin", "is_active": False},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "user"
        assert resp.json()["is_active"] is True

    def test_me_email_conflict_409(self, client, regular_user, other_user):
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            "/users/me", json={"email": other_user.email}, headers=headers
        )
        assert resp.status_code == 409
        assert "email" in resp.json()["detail"].lower()

    def test_me_username_conflict_409(self, client, regular_user, other_user):
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            "/users/me", json={"username": other_user.username}, headers=headers
        )
        assert resp.status_code == 409

    def test_me_email_update(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            "/users/me", json={"email": "alice-updated@example.com"}, headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice-updated@example.com"
