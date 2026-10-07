"""Project endpoint tests: full authorization matrix + 403-vs-404 ordering."""

from __future__ import annotations

from tests.conftest import auth_headers, make_project

CREATE = {"name": "My Project", "description": "created via api"}


class TestCreate:
    def test_create_project_success(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        resp = client.post("/projects", json=CREATE, headers=headers)
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "My Project"
        assert body["owner_id"] == regular_user.id
        assert "id" in body

    def test_create_project_requires_auth(self, client):
        assert client.post("/projects", json=CREATE).status_code == 401

    def test_create_project_inactive_rejected(self, client, session, regular_user):
        from app.core.security import create_access_token

        token = create_access_token(regular_user.id, regular_user.email, "user")
        regular_user.is_active = False
        session.commit()
        resp = client.post(
            "/projects", json=CREATE, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    def test_create_project_blank_name_422(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.post("/projects", json={"name": ""}, headers=headers).status_code == 422


class TestOwnershipMatrix:
    """anonymous / owner / non-owner / admin / inactive against a project."""

    def test_anonymous_cannot_read_project(self, client, session, regular_user):
        project = make_project(session, regular_user)
        assert client.get(f"/projects/{project.id}").status_code == 401

    def test_anonymous_cannot_list_projects(self, client):
        assert client.get("/projects").status_code == 401

    def test_owner_can_read_own_project(self, client, session, regular_user):
        project = make_project(session, regular_user, name="Alice's")
        headers = auth_headers(client, regular_user)
        resp = client.get(f"/projects/{project.id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "Alice's"

    def test_owner_can_update_own_project(self, client, session, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.patch(
            f"/projects/{project.id}", json={"name": "Renamed"}, headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Renamed"

    def test_owner_can_delete_own_project(self, client, session, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, regular_user)
        assert client.delete(f"/projects/{project.id}", headers=headers).status_code == 204
        # After deletion the resource no longer exists. Per requirement 7 a
        # non-admin caller never receives 404 (anti-enumeration): 403 is correct.
        assert client.get(f"/projects/{project.id}", headers=headers).status_code == 403

    def test_nonadmin_read_missing_project_403(self, client, regular_user):
        # Requirement 7: a non-owner receives 403 regardless of existence.
        headers = auth_headers(client, regular_user)
        assert client.get("/projects/999999", headers=headers).status_code == 403

    def test_nonowner_read_existing_project_403(self, client, session, regular_user, other_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, other_user)
        # Project EXISTS, but non-owner still gets 403 (never 200/404).
        resp = client.get(f"/projects/{project.id}", headers=headers)
        assert resp.status_code == 403

    def test_nonowner_read_missing_project_403(self, client, regular_user, other_user):
        # Project does NOT exist; non-owner still gets 403 (same as existing).
        headers = auth_headers(client, other_user)
        assert client.get("/projects/999999", headers=headers).status_code == 403

    def test_nonowner_update_foreign_project_403(self, client, session, regular_user, other_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, other_user)
        resp = client.patch(
            f"/projects/{project.id}", json={"name": "Hax"}, headers=headers
        )
        assert resp.status_code == 403

    def test_nonowner_delete_foreign_project_403(self, client, session, regular_user, other_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, other_user)
        assert client.delete(f"/projects/{project.id}", headers=headers).status_code == 403

    def test_regular_user_cannot_list_others_projects(self, client, session, regular_user, other_user):
        make_project(session, regular_user, name="Alice's")
        make_project(session, other_user, name="Bob's")
        headers = auth_headers(client, other_user)
        resp = client.get("/projects", headers=headers)
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()["items"]]
        assert names == ["Bob's"]

    def test_inactive_owner_cannot_touch_own_project(self, client, session, regular_user):
        from app.core.security import create_access_token

        project = make_project(session, regular_user)
        token = create_access_token(regular_user.id, regular_user.email, "user")
        regular_user.is_active = False
        session.commit()
        resp = client.get(
            f"/projects/{project.id}", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403


class TestAdminAccess:
    def test_admin_can_read_any_project(self, client, session, admin, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, admin)
        assert client.get(f"/projects/{project.id}", headers=headers).status_code == 200

    def test_admin_can_read_missing_project_404(self, client, admin):
        headers = auth_headers(client, admin)
        assert client.get("/projects/999999", headers=headers).status_code == 404

    def test_admin_can_update_foreign_project(self, client, session, admin, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, admin)
        resp = client.patch(
            f"/projects/{project.id}", json={"description": "admin edited"}, headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["description"] == "admin edited"

    def test_admin_can_delete_foreign_project(self, client, session, admin, regular_user):
        project = make_project(session, regular_user)
        headers = auth_headers(client, admin)
        assert client.delete(f"/projects/{project.id}", headers=headers).status_code == 204

    def test_admin_sees_all_projects_in_list(self, client, session, admin, regular_user, other_user):
        make_project(session, regular_user, name="Alice's")
        make_project(session, other_user, name="Bob's")
        headers = auth_headers(client, admin)
        resp = client.get("/projects", headers=headers)
        assert resp.status_code == 200
        names = {p["name"] for p in resp.json()["items"]}
        assert names == {"Alice's", "Bob's"}
