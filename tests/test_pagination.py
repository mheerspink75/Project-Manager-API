"""Pagination behavior: default page size, server max, out-of-range pages."""

from __future__ import annotations

from tests.conftest import auth_headers

TOTAL_PROJECTS = 25


def seed_projects(client, session, user, count: int = TOTAL_PROJECTS) -> None:
    headers = auth_headers(client, user)
    for i in range(count):
        resp = client.post(
            "/projects", json={"name": f"Project {i:02d}"}, headers=headers
        )
        assert resp.status_code == 201, resp.text


class TestProjectPagination:
    def test_default_page_size(self, client, session, regular_user):
        seed_projects(client, session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 20  # documented default
        assert body["offset"] == 0
        assert body["total"] == TOTAL_PROJECTS
        assert len(body["items"]) == 20

    def test_explicit_limit_and_offset(self, client, session, regular_user):
        seed_projects(client, session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects?limit=5&offset=10", headers=headers)
        body = resp.json()
        assert body["limit"] == 5
        assert body["offset"] == 10
        assert body["total"] == TOTAL_PROJECTS
        assert len(body["items"]) == 5
        assert body["items"][0]["name"] == "Project 10"

    def test_out_of_range_offset_returns_empty_page(self, client, session, regular_user):
        seed_projects(client, session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects?offset=9999", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == TOTAL_PROJECTS

    def test_limit_above_max_rejected(self, client, session, regular_user):
        seed_projects(client, session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects?limit=10000", headers=headers)
        assert resp.status_code == 422

    def test_limit_at_max_allowed(self, client, session, regular_user):
        seed_projects(client, session, regular_user)
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects?limit=100", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["limit"] == 100
        assert len(resp.json()["items"]) == TOTAL_PROJECTS

    def test_zero_limit_rejected(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.get("/projects?limit=0", headers=headers).status_code == 422

    def test_negative_offset_rejected(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        assert client.get("/projects?offset=-1", headers=headers).status_code == 422

    def test_empty_list_paginated(self, client, regular_user):
        headers = auth_headers(client, regular_user)
        resp = client.get("/projects", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0


class TestUserPagination:
    def test_user_list_default_page(self, client, admin, session):
        from tests.conftest import make_user

        for i in range(30):
            make_user(
                session,
                email=f"bulk{i}@example.com",
                username=f"bulk{i}",
            )
        headers = auth_headers(client, admin)
        resp = client.get("/users", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 20
        assert body["total"] == 31  # 30 bulk + admin
        assert len(body["items"]) == 20

    def test_user_list_limit_cap(self, client, admin):
        headers = auth_headers(client, admin)
        resp = client.get("/users?limit=5000", headers=headers)
        assert resp.status_code == 422
