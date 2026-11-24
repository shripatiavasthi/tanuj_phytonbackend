from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError

import app as backend


class InMemoryUsers:
    def __init__(self) -> None:
        self.documents: dict[str, dict] = {}

    def insert_one(self, document: dict) -> SimpleNamespace:
        if document["email"] in self.documents:
            raise DuplicateKeyError("duplicate email")
        stored = {**document, "_id": f"user-{len(self.documents) + 1}"}
        self.documents[document["email"]] = stored
        return SimpleNamespace(inserted_id=stored["_id"])

    def find_one(self, query: dict) -> dict | None:
        return self.documents.get(query["email"])


class InMemoryAdmins:
    def __init__(self) -> None:
        self.document: dict | None = None

    def create_index(self, *_args, **_kwargs) -> None:
        return None

    def find_one(self, query: dict) -> dict | None:
        if self.document is None:
            return None
        if query.get("_id") == self.document["_id"] or query.get("email") == self.document["email"]:
            return self.document
        return None

    def insert_one(self, document: dict) -> SimpleNamespace:
        if self.document is not None:
            raise DuplicateKeyError("duplicate admin")
        self.document = document
        return SimpleNamespace(inserted_id=document["_id"])


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    users = InMemoryUsers()
    admins = InMemoryAdmins()
    monkeypatch.setattr(backend, "users_collection", lambda: users)
    monkeypatch.setattr(backend, "admins_collection", lambda: admins)
    monkeypatch.setenv("JWT_SECRET", "test-secret-with-sufficient-length")
    monkeypatch.setenv("CRM_ADMIN_SETUP_SECRET", "test-setup-secret-at-least-32-characters")
    return TestClient(backend.app)


def test_health_check(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_register_returns_compatible_user_and_jwt(client: TestClient) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "name": "  Test Consumer  ",
            "email": "Consumer@example.com",
            "phone": "",
            "password": "secure-test-password",
            "role": "consumer",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["user"] == {
        "id": "user-1",
        "name": "Test Consumer",
        "email": "consumer@example.com",
        "role": "consumer",
        "phone": None,
    }
    assert jwt.decode(
        result["token"],
        "test-secret-with-sufficient-length",
        algorithms=["HS256"],
    )["sub"] == "user-1"
    assert "password_hash" not in result["user"]


def test_register_rejects_duplicate_email(client: TestClient) -> None:
    payload = {
        "name": "Test Provider",
        "email": "provider@example.com",
        "password": "secure-test-password",
        "role": "provider",
    }
    assert client.post("/api/auth/register", json=payload).status_code == 200
    response = client.post("/api/auth/register", json=payload)

    assert response.status_code == 409
    assert response.json()["detail"] == "An account with this email already exists"


def test_login_is_case_insensitive_and_rejects_wrong_password(client: TestClient) -> None:
    client.post(
        "/api/auth/register",
        json={
            "name": "Test Consumer",
            "email": "consumer@example.com",
            "password": "secure-test-password",
        },
    )

    success = client.post(
        "/api/auth/login",
        json={"email": "CONSUMER@example.com", "password": "secure-test-password"},
    )
    failure = client.post(
        "/api/auth/login",
        json={"email": "consumer@example.com", "password": "incorrect-password"},
    )

    assert success.status_code == 200
    assert success.json()["user"]["email"] == "consumer@example.com"
    assert failure.status_code == 401
    assert failure.json()["detail"] == "Invalid email or password"


def test_registration_rejects_admin_role(client: TestClient) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Unexpected Admin",
            "email": "admin@example.com",
            "password": "secure-test-password",
            "role": "admin",
        },
    )

    assert response.status_code == 422


def test_admin_setup_is_one_time_and_requires_setup_secret(client: TestClient) -> None:
    payload = {
        "name": "CRM Owner",
        "email": "OWNER@example.com",
        "password": "secure-admin-password",
    }

    unauthorized = client.post("/api/admin/setup", json=payload)
    created = client.post(
        "/api/admin/setup",
        headers={"X-Admin-Setup-Secret": "test-setup-secret-at-least-32-characters"},
        json=payload,
    )
    second_setup = client.post(
        "/api/admin/setup",
        headers={"X-Admin-Setup-Secret": "test-setup-secret-at-least-32-characters"},
        json=payload,
    )

    assert unauthorized.status_code == 401
    assert created.status_code == 201
    assert created.json()["admin"] == {
        "id": "primary",
        "name": "CRM Owner",
        "email": "owner@example.com",
    }
    assert "password_hash" not in created.json()["admin"]
    assert second_setup.status_code == 409


def test_admin_login_and_admin_only_user_creation(client: TestClient) -> None:
    client.post(
        "/api/admin/setup",
        headers={"X-Admin-Setup-Secret": "test-setup-secret-at-least-32-characters"},
        json={
            "name": "CRM Owner",
            "email": "owner@example.com",
            "password": "secure-admin-password",
        },
    )
    login = client.post(
        "/api/admin/login",
        json={"email": "OWNER@example.com", "password": "secure-admin-password"},
    )
    invalid_login = client.post(
        "/api/admin/login",
        json={"email": "owner@example.com", "password": "incorrect-password"},
    )
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    created_user = client.post(
        "/api/admin/users",
        headers=headers,
        json={
            "name": "Managed Consumer",
            "email": "managed@example.com",
            "password": "secure-user-password",
            "role": "consumer",
        },
    )

    assert login.status_code == 200
    assert login.json()["admin"]["email"] == "owner@example.com"
    assert invalid_login.status_code == 401
    assert created_user.status_code == 200
    assert created_user.json()["user"]["email"] == "managed@example.com"
    assert "token" not in created_user.json()


def test_admin_only_service_creation_rejects_non_admin_token(client: TestClient) -> None:
    consumer = client.post(
        "/api/auth/register",
        json={
            "name": "Regular User",
            "email": "regular@example.com",
            "password": "secure-user-password",
        },
    )
    response = client.post(
        "/api/services",
        headers={"Authorization": f"Bearer {consumer.json()['token']}"},
        json={"name": "Nursing Care"},
    )

    assert response.status_code == 403
