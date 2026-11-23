from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient
from bson import ObjectId

import app as backend


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch):
    database = mongomock.MongoClient().careconnect_test
    service_id = ObjectId()
    database.services.insert_one(
        {
            "_id": service_id,
            "name": "Nursing Care",
            "description": "At-home nursing",
            "image_url": "https://example.com/nursing.jpg",
        }
    )
    monkeypatch.setattr(backend, "users_collection", lambda: database.users)
    monkeypatch.setattr(backend, "collection", lambda name: database[name])
    monkeypatch.setenv("JWT_SECRET", "test-secret-with-sufficient-length")
    return TestClient(backend.app), database, service_id


def register(api, role: str, email: str) -> tuple[str, str]:
    client, _, _ = api
    response = client.post(
        "/api/auth/register",
        json={
            "name": role.title(),
            "email": email,
            "phone": "1234567890",
            "password": "secure-test-password",
            "role": role,
        },
    )
    assert response.status_code == 200
    result = response.json()
    return result["token"], result["user"]["id"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_services_and_consumer_request_lifecycle(api) -> None:
    client, database, service_id = api
    consumer_token, consumer_id = register(api, "consumer", "consumer@example.com")

    services = client.get("/api/services")
    created = client.post(
        "/api/requests",
        headers=auth(consumer_token),
        data={
            "service_id": str(service_id),
            "address": "10 Test Street",
            "notes": "Please call before arrival",
            "lat": "12.5",
            "lng": "77.6",
        },
    )

    assert services.status_code == 200
    assert services.json()[0]["id"] == str(service_id)
    assert created.status_code == 200
    assert created.json()["status"] == "pending_approval"
    assert created.json()["service_name"] == "Nursing Care"

    request_id = created.json()["id"]
    mine = client.get("/api/requests/mine", headers=auth(consumer_token))
    detail = client.get(f"/api/requests/{request_id}", headers=auth(consumer_token))
    assert [item["id"] for item in mine.json()] == [request_id]
    assert detail.json()["consumer_id"] == consumer_id

    cancelled = client.patch(f"/api/requests/{request_id}/cancel", headers=auth(consumer_token))
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert len(cancelled.json()["status_history"]) == 2
    assert database.requests.count_documents({"consumer_id": ObjectId(consumer_id)}) == 1


def test_provider_quote_booking_profile_stats_and_notifications(api) -> None:
    client, database, service_id = api
    consumer_token, consumer_id = register(api, "consumer", "consumer@example.com")
    provider_token, provider_id = register(api, "provider", "provider@example.com")
    created = client.post(
        "/api/requests",
        headers=auth(consumer_token),
        data={"service_id": str(service_id), "address": "20 Test Street"},
    )
    request_id = created.json()["id"]
    request_object_id = ObjectId(request_id)
    database.requests.update_one(
        {"_id": request_object_id},
        {"$set": {"status": "notified"}},
    )

    available = client.get("/api/providers/me/available", headers=auth(provider_token))
    assert available.status_code == 200
    assert available.json()[0]["consumer_name"] == "Consumer"
    assert available.json()[0]["already_quoted"] is False

    quote = client.post(
        "/api/quotes",
        headers=auth(provider_token),
        json={"request_id": request_id, "amount": 1250, "note": "Includes travel"},
    )
    assert quote.status_code == 200
    assert database.requests.find_one({"_id": request_object_id})["status"] == "quoted"
    assert client.get("/api/providers/me/available", headers=auth(provider_token)).json()[0]["already_quoted"] is True
    assert client.get("/api/notifications/mine", headers=auth(consumer_token)).json()[0]["title"] == "New provider quote"

    duplicate = client.post(
        "/api/quotes",
        headers=auth(provider_token),
        json={"request_id": request_id, "amount": 1300},
    )
    assert duplicate.status_code == 409

    database.requests.update_one(
        {"_id": request_object_id},
        {
            "$set": {
                "status": "awarded",
                "provider_id": ObjectId(provider_id),
                "provider_name": "Provider",
                "provider_phone": "1234567890",
                "final_price": 1250,
            }
        },
    )
    bookings = client.get("/api/providers/me/requests", headers=auth(provider_token))
    assert bookings.status_code == 200
    assert bookings.json()[0]["consumer_id"] == consumer_id

    profile = client.get("/api/providers/me/profile", headers=auth(provider_token))
    assert profile.json() == {"available": True}
    updated = client.put(
        "/api/providers/me/profile",
        headers=auth(provider_token),
        json={"available": False},
    )
    assert updated.json() == {"available": False}
    assert client.get("/api/providers/me/available", headers=auth(provider_token)).json() == []
    assert client.put(
        "/api/providers/me/profile",
        headers=auth(provider_token),
        json={"available": True},
    ).status_code == 200

    scheduled_at = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    scheduled = client.patch(
        f"/api/requests/{request_id}/schedule",
        headers=auth(provider_token),
        json={"scheduled_at": scheduled_at},
    )
    assert scheduled.status_code == 200
    assert scheduled.json()["status"] == "scheduled"
    completed = client.patch(f"/api/requests/{request_id}/complete", headers=auth(provider_token))
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"

    stats = client.get("/api/providers/me/stats", headers=auth(provider_token))
    assert stats.json() == {
        "earned": 1250,
        "fulfilled": 1,
        "active": 0,
        "quotes_won": 0,
        "quotes_lost": 0,
        "quotes_pending": 1,
    }

    consumer_notifications = client.get("/api/notifications/mine", headers=auth(consumer_token))
    assert [item["title"] for item in consumer_notifications.json()] == [
        "Service completed",
        "Service scheduled",
        "New provider quote",
    ]
    read_all = client.patch("/api/notifications/read-all", headers=auth(consumer_token))
    assert read_all.status_code == 200
    assert all(item["read"] for item in client.get("/api/notifications/mine", headers=auth(consumer_token)).json())


def test_fcm_token_requires_authentication_and_is_stored(api) -> None:
    client, database, _ = api
    token, user_id = register(api, "consumer", "consumer@example.com")

    unauthorized = client.patch("/api/auth/fcm-token", json={"fcm_token": "device-token"})
    stored = client.patch(
        "/api/auth/fcm-token",
        headers=auth(token),
        json={"fcm_token": "device-token"},
    )

    assert unauthorized.status_code == 401
    assert stored.status_code == 200
    assert database.users.find_one({"_id": ObjectId(user_id)})["fcm_token"] == "device-token"


def test_prescription_upload_uses_configured_object_storage(api, monkeypatch: pytest.MonkeyPatch) -> None:
    client, database, service_id = api
    consumer_token, _ = register(api, "consumer", "consumer@example.com")
    uploads = []

    class FakeS3:
        def put_object(self, **kwargs) -> None:
            uploads.append(kwargs)

    monkeypatch.setenv("S3_BUCKET", "careconnect-test")
    monkeypatch.setattr(backend.boto3, "client", lambda *args, **kwargs: FakeS3())
    response = client.post(
        "/api/requests",
        headers=auth(consumer_token),
        data={"service_id": str(service_id), "address": "30 Test Street"},
        files={"prescription": ("prescription.jpg", b"test-image", "image/jpeg")},
    )

    assert response.status_code == 200
    assert uploads[0]["Bucket"] == "careconnect-test"
    assert uploads[0]["Body"] == b"test-image"
    saved = database.requests.find_one({"_id": ObjectId(response.json()["id"])})
    assert saved["prescription_key"].startswith("prescriptions/")
