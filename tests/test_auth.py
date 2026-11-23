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


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    users = InMemoryUsers()
    monkeypatch.setattr(backend, "users_collection", lambda: users)
    monkeypatch.setenv("JWT_SECRET", "test-secret-with-sufficient-length")
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
