"""Audit log tests: admin mutations are recorded; secrets never are."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.models.audit_log import AuditLog
from tests.conftest import auth_headers, make_project


class TestAuditEndpoint:
    def test_admin_can_list_audit_entries(self, client, session, admin, other_user):
        headers = auth_headers(client, admin)
        # Generate one audited mutation.
        assert (
            client.patch(
                f"/users/{other_user.id}", json={"role": "admin"}, headers=headers
            ).status_code
            == 200
        )
        resp = client.get("/audit", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        entry = body["items"][0]
        assert entry["action"] == "user.update"
        assert entry["actor_email"] == admin.email
        assert entry["created_at"] is not None
        # Audit entries never carry passwords.
        assert "S3cure" not in entry["detail"]

    def test_regular_user_cannot_list_audit(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.get("/audit", headers=headers).status_code == 403

    def test_anonymous_cannot_list_audit(self, client):
        assert client.get("/audit").status_code == 401

    def test_audit_pagination(self, client, session, admin, other_user):
        headers = auth_headers(client, admin)
        for i in range(3):
            assert (
                client.patch(
                    f"/users/{other_user.id}", json={"is_active": True}, headers=headers
                ).status_code
                == 200
            )
        resp = client.get("/audit?limit=2&offset=1", headers=headers)
        body = resp.json()
        assert body["limit"] == 2
        assert body["offset"] == 1
        assert body["total"] == 3
        assert len(body["items"]) == 2


class TestAuditSanitization:
    def test_empty_detail_serializes_to_empty_string(self):
        from app.core.audit import sanitize_detail

        assert sanitize_detail({}) == ""
        assert sanitize_detail(None) == ""

    def test_sensitive_keys_stripped_recursively(self):
        import json

        from app.core.audit import sanitize_detail

        raw = {
            "username": "bob",
            "password": "S3cure-Passw0rd",
            "nested": {"access_token": "abc", "role": "admin"},
            "items": [{"refresh_token": "x", "name": "ok"}],
        }
        cleaned = json.loads(sanitize_detail(raw))
        assert "password" not in cleaned
        assert "access_token" not in cleaned["nested"]
        assert "refresh_token" not in cleaned["items"][0]
        assert cleaned["username"] == "bob"
        assert cleaned["nested"]["role"] == "admin"
        assert cleaned["items"][0]["name"] == "ok"


class TestAuditUserMutations:
    def test_admin_create_user_audited(self, client, session, admin):
        headers = auth_headers(client, admin)
        resp = client.post(
            "/users",
            json={
                "email": "audited@example.com",
                "username": "audited",
                "password": "S3cure-Passw0rd",
            },
            headers=headers,
        )
        assert resp.status_code == 201
        rows = session.execute(
            select(AuditLog).where(AuditLog.action == "user.create")
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].actor_email == admin.email
        assert rows[0].resource_type == "user"
        assert rows[0].resource_id == str(resp.json()["id"])

    def test_admin_update_user_audited(self, client, session, admin, other_user):
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}", json={"role": "admin"}, headers=headers
        )
        assert resp.status_code == 200
        rows = session.execute(
            select(AuditLog).where(
                AuditLog.action == "user.update",
                AuditLog.resource_id == str(other_user.id),
            )
        ).scalars().all()
        assert len(rows) == 1
        detail = json.loads(rows[0].detail)
        assert detail["role"] == "admin"

    def test_admin_delete_user_audited(self, client, session, admin, other_user):
        headers = auth_headers(client, admin)
        victim_id = other_user.id
        assert client.delete(f"/users/{victim_id}", headers=headers).status_code == 204
        rows = session.execute(
            select(AuditLog).where(
                AuditLog.action == "user.delete",
                AuditLog.resource_id == str(victim_id),
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].actor_email == admin.email

    def test_audit_detail_never_contains_passwords(self, client, session, admin, other_user):
        raw_password = "S3cure-Passw0rd"
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/users/{other_user.id}",
            json={"password": raw_password, "role": "admin"},
            headers=headers,
        )
        assert resp.status_code == 200
        rows = session.execute(select(AuditLog)).scalars().all()
        assert rows, "expected at least one audit entry"
        for row in rows:
            assert raw_password not in row.detail
            detail = json.loads(row.detail) if row.detail else {}
            # the raw password value must not appear under any key
            values = json.dumps(detail)
            assert raw_password not in values
            assert "hashed_password" not in detail


class TestAuditProjectMutations:
    def test_admin_override_update_audited(self, client, session, admin, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/projects/{project.id}", json={"name": "Admin edited"}, headers=headers
        )
        assert resp.status_code == 200
        rows = session.execute(
            select(AuditLog).where(
                AuditLog.action == "project.update",
                AuditLog.resource_id == str(project.id),
            )
        ).scalars().all()
        assert len(rows) == 1
        detail = json.loads(rows[0].detail)
        assert detail["admin_override"] is True
        assert detail["owner_id"] == regular_user.id

    def test_admin_delete_audited(self, client, session, admin, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, admin)
        assert client.delete(f"/projects/{project.id}", headers=headers).status_code == 204
        rows = session.execute(
            select(AuditLog).where(
                AuditLog.action == "project.delete",
                AuditLog.resource_id == str(project.id),
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].actor_email == admin.email

    def test_admin_create_audited(self, client, session, admin):
        headers = auth_headers(client, admin)
        resp = client.post(
            "/projects", json={"name": "Admin project"}, headers=headers
        )
        assert resp.status_code == 201
        rows = session.execute(
            select(AuditLog).where(
                AuditLog.action == "project.create",
                AuditLog.resource_id == str(resp.json()["id"]),
            )
        ).scalars().all()
        assert len(rows) == 1

    def test_regular_owner_mutation_not_audited(self, client, session, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, regular_user)
        assert (
            client.patch(
                f"/projects/{project.id}", json={"name": "mine"}, headers=headers
            ).status_code
            == 200
        )
        rows = session.execute(select(AuditLog)).scalars().all()
        assert rows == [], "non-admin owner mutations must not create audit entries"

    def test_audit_row_has_when(self, client, session, admin, other_user):
        headers = auth_headers(client, admin)
        client.patch(f"/users/{other_user.id}", json={"role": "admin"}, headers=headers)
        row = session.execute(
            select(AuditLog).order_by(AuditLog.id.desc())
        ).scalars().first()
        assert row.created_at is not None  # "when" is recorded
