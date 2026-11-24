import base64
import binascii
import hmac
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

import boto3
import jwt
import certifi
from bson import ObjectId
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field, field_validator
from pwdlib import PasswordHash
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError, PyMongoError

logger = logging.getLogger("careconnect")
password_hash = PasswordHash.recommended()
load_dotenv(Path(__file__).with_name(".env"), override=False)
bearer_scheme = HTTPBearer(auto_error=False)


class RequestStatus(StrEnum):
    pending_approval = "pending_approval"
    approved = "approved"
    notified = "notified"
    quoted = "quoted"
    awarded = "awarded"
    scheduled = "scheduled"
    completed = "completed"
    rejected = "rejected"
    cancelled = "cancelled"


class QuoteRequest(BaseModel):
    request_id: str
    amount: Annotated[float, Field(gt=0, le=10_000_000)]
    note: Annotated[str, Field(max_length=1000)] = ""


class ScheduleRequest(BaseModel):
    scheduled_at: datetime


class FcmTokenRequest(BaseModel):
    fcm_token: Annotated[str, Field(min_length=1, max_length=4096)]


class ProviderProfileUpdate(BaseModel):
    available: bool


def validate_catalog_image(value: str | None) -> str | None:
    if value is None:
        return None
    prefix, separator, encoded = value.partition(",")
    supported_types = {
        "data:image/jpeg;base64",
        "data:image/png;base64",
        "data:image/webp;base64",
    }
    if not separator or prefix.lower() not in supported_types:
        raise ValueError("Image must be a base64 JPEG, PNG, or WebP data URL")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("Image must contain valid base64 data") from error
    if not decoded or len(decoded) > 5 * 1024 * 1024:
        raise ValueError("Image must be between 1 byte and 5 MB")
    image_signatures = {
        "data:image/jpeg;base64": decoded.startswith(b"\xff\xd8\xff"),
        "data:image/png;base64": decoded.startswith(b"\x89PNG\r\n\x1a\n"),
        "data:image/webp;base64": decoded.startswith(b"RIFF") and decoded[8:12] == b"WEBP",
    }
    if not image_signatures[prefix.lower()]:
        raise ValueError("Image data does not match its declared format")
    return value


class ServiceSubService(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str, Field(max_length=1000)] = ""
    icon: Annotated[str, Field(max_length=16)] = ""
    image_url: Annotated[str | None, Field(max_length=7_000_000)] = None

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Subservice name must not be blank")
        return normalized

    @field_validator("image_url")
    @classmethod
    def validate_image(cls, value: str | None) -> str | None:
        return validate_catalog_image(value)


class ServiceCreateRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str, Field(max_length=2000)] = ""
    image_url: Annotated[str | None, Field(max_length=7_000_000)] = None
    sub_services: Annotated[list[ServiceSubService], Field(max_length=100)] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Service name must not be blank")
        return normalized

    @field_validator("image_url")
    @classmethod
    def validate_base64_image(cls, value: str | None) -> str | None:
        return validate_catalog_image(value)


class UserRole(StrEnum):
    consumer = "consumer"
    provider = "provider"


class RegisterRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]
    phone: Annotated[str | None, Field(max_length=32)] = None
    role: UserRole = UserRole.consumer

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Name must not be blank")
        return normalized

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class LoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()


class AdminSetupRequest(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    email: EmailStr
    password: Annotated[str, Field(min_length=12, max_length=128)]

    @field_validator("name")
    @classmethod
    def trim_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Name must not be blank")
        return normalized

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()


class PublicUser(BaseModel):
    id: str
    name: str
    email: str
    role: UserRole
    phone: str | None = None


class AuthResponse(BaseModel):
    token: str
    user: PublicUser


class AdminAuthResponse(BaseModel):
    token: str
    admin: dict[str, str]


app = FastAPI(title="CareConnect API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def mongo_client(uri: str) -> MongoClient:
    return MongoClient(uri, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)


@lru_cache(maxsize=1)
def database(uri: str, database_name: str):
    return mongo_client(uri)[database_name]


@lru_cache(maxsize=1)
def configured_users_collection(uri: str, database_name: str) -> Collection:
    try:
        collection = database(uri, database_name)["users"]
        collection.create_index("email", unique=True)
        return collection
    except PyMongoError as error:
        logger.exception("Could not initialize the users collection")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database is unavailable",
        ) from error


def users_collection() -> Collection:
    uri = os.getenv("MONGODB_URI")
    if not uri or uri.startswith("YOUR_"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Set MONGODB_URI to a valid MongoDB connection string",
        )
    database_name = os.getenv("MONGODB_DATABASE", "careconnect")
    configured_users_collection(uri, database_name)
    return database(uri, database_name)["users"]


def admins_collection() -> Collection:
    admins = collection("admins")
    try:
        admins.create_index("email", unique=True)
    except PyMongoError as error:
        logger.exception("Could not initialize the admins collection")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin authentication database is unavailable",
        ) from error
    return admins


def collection(name: str) -> Collection:
    uri = os.getenv("MONGODB_URI")
    if not uri or uri.startswith("YOUR_"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Set MONGODB_URI to a valid MongoDB connection string",
        )
    try:
        return database(uri, os.getenv("MONGODB_DATABASE", "careconnect"))[name]
    except PyMongoError as error:
        logger.exception("Could not access database collection %s", name)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        ) from error


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret or len(secret) < 32 or secret.startswith("REPLACE_WITH_"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Set JWT_SECRET to a random value of at least 32 characters",
        )
    return secret


def public_user(document: dict[str, Any]) -> PublicUser:
    return PublicUser(
        id=str(document["_id"]),
        name=document["name"],
        email=document["email"],
        role=UserRole(document["role"]),
        phone=document.get("phone"),
    )


def issue_token(user: PublicUser) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user.id,
        "role": user.role.value,
        "iat": now,
        "exp": now + timedelta(hours=24),
    }
    return jwt.encode(claims, jwt_secret(), algorithm="HS256")


def issue_admin_token(admin_id: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": admin_id,
        "role": "admin",
        "iat": now,
        "exp": now + timedelta(hours=12),
    }
    return jwt.encode(claims, jwt_secret(), algorithm="HS256")


def require_auth(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        claims = jwt.decode(credentials.credentials, jwt_secret(), algorithms=["HS256"])
        subject = claims.get("sub")
        role = claims.get("role")
    except (jwt.InvalidTokenError, ValueError, TypeError) as error:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from error
    if not subject or role not in {UserRole.consumer.value, UserRole.provider.value, "admin"}:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return {"id": subject, "role": role}


def require_admin(user: Annotated[dict[str, Any], Depends(require_auth)]) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_role(role: UserRole):
    def dependency(user: Annotated[dict[str, Any], Depends(require_auth)]) -> dict[str, Any]:
        if user["role"] != role.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


def mongo_id(value: str) -> ObjectId:
    if not ObjectId.is_valid(value):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return ObjectId(value)


def isoformat(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, ObjectId):
        return str(value)
    return value


def request_view(document: dict[str, Any]) -> dict[str, Any]:
    history = [
        {key: isoformat(value) for key, value in item.items()}
        for item in document.get("status_history", [])
    ]
    return {
        "id": str(document["_id"]),
        "service_id": str(document["service_id"]),
        "service_name": document.get("service_name", "Service"),
        "description": document.get("description", ""),
        "image_url": document.get("image_url"),
        "consumer_id": str(document["consumer_id"]),
        "consumer_name": document.get("consumer_name", ""),
        "consumer_phone": document.get("consumer_phone"),
        "provider_id": str(document["provider_id"]) if document.get("provider_id") else None,
        "provider_name": document.get("provider_name"),
        "provider_phone": document.get("provider_phone"),
        "address": document["address"],
        "notes": document.get("notes", ""),
        "lat": document.get("lat"),
        "lng": document.get("lng"),
        "status": document["status"],
        "final_price": document.get("final_price"),
        "scheduled_at": isoformat(document.get("scheduled_at")),
        "status_history": history,
        "created_at": isoformat(document["created_at"]),
    }


def notification_view(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(document["_id"]),
        "title": document["title"],
        "body": document["body"],
        "read": bool(document.get("read", False)),
        "created_at": isoformat(document["created_at"]),
    }


def add_notification(user_id: ObjectId, title: str, body: str) -> None:
    collection("notifications").insert_one(
        {
            "user_id": user_id,
            "title": title,
            "body": body,
            "read": False,
            "created_at": datetime.now(timezone.utc),
        }
    )


def attach_prescription(upload: UploadFile, request_id: str, user_id: str) -> str:
    bucket = os.getenv("S3_BUCKET")
    if not bucket:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Prescription uploads are not configured",
        )
    allowed_types = {"image/jpeg", "image/png", "image/webp", "application/pdf"}
    content_type = upload.content_type or "application/octet-stream"
    if content_type not in allowed_types:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported prescription file type")
    content = upload.file.read(10 * 1024 * 1024 + 1)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Prescription file exceeds 10 MB")
    extension = Path(upload.filename or "").suffix[:12]
    key = f"prescriptions/{user_id}/{request_id}/{uuid.uuid4().hex}{extension}"
    try:
        s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION"))
        s3.put_object(Bucket=bucket, Key=key, Body=content, ContentType=content_type)
    except Exception as error:
        logger.exception("Could not upload prescription to object storage")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Prescription upload failed",
        ) from error
    return key


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "CareConnect API", "health": "/api/health"}


@app.get("/api/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/auth/register", response_model=AuthResponse)
def register(payload: RegisterRequest) -> AuthResponse:
    jwt_secret()
    user = insert_user(payload)
    return AuthResponse(token=issue_token(user), user=user)


def insert_user(payload: RegisterRequest) -> PublicUser:
    user_documents = users_collection()
    document = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": password_hash.hash(payload.password),
        "role": payload.role.value,
        "phone": payload.phone,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        result = user_documents.insert_one(document)
    except DuplicateKeyError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        ) from error
    except PyMongoError as error:
        logger.exception("Could not register user")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database is unavailable",
        ) from error

    document["_id"] = result.inserted_id
    return public_user(document)


@app.post("/api/admin/setup", response_model=AdminAuthResponse, status_code=status.HTTP_201_CREATED)
def setup_admin(
    payload: AdminSetupRequest,
    setup_secret: Annotated[str | None, Header(alias="X-Admin-Setup-Secret")] = None,
) -> AdminAuthResponse:
    jwt_secret()
    configured_secret = os.getenv("CRM_ADMIN_SETUP_SECRET")
    if not configured_secret or len(configured_secret) < 32 or configured_secret.startswith("REPLACE_WITH_"):
        raise HTTPException(status_code=503, detail="Admin setup is not configured")
    if not setup_secret or not hmac.compare_digest(setup_secret, configured_secret):
        raise HTTPException(status_code=401, detail="Invalid or missing admin setup secret")

    admins = admins_collection()
    try:
        if admins.find_one({"_id": "primary"}) is not None:
            raise HTTPException(status_code=409, detail="The CRM admin account has already been created")
        document = {
            "_id": "primary",
            "name": payload.name,
            "email": payload.email,
            "password_hash": password_hash.hash(payload.password),
            "created_at": datetime.now(timezone.utc),
        }
        admins.insert_one(document)
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="The CRM admin account has already been created") from error
    except PyMongoError as error:
        logger.exception("Could not create CRM admin account")
        raise HTTPException(
            status_code=503,
            detail="Admin authentication database is unavailable",
        ) from error

    return AdminAuthResponse(
        token=issue_admin_token("primary"),
        admin={"id": "primary", "name": document["name"], "email": document["email"]},
    )


@app.post("/api/admin/login", response_model=AdminAuthResponse)
def login_admin(payload: AdminLoginRequest) -> AdminAuthResponse:
    jwt_secret()
    try:
        document = admins_collection().find_one({"email": payload.email})
    except PyMongoError as error:
        logger.exception("Could not look up CRM admin for login")
        raise HTTPException(
            status_code=503,
            detail="Admin authentication database is unavailable",
        ) from error

    if not document or not password_hash.verify(payload.password, document["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return AdminAuthResponse(
        token=issue_admin_token(str(document["_id"])),
        admin={"id": str(document["_id"]), "name": document["name"], "email": document["email"]},
    )


@app.post("/api/admin/users")
def create_user_as_admin(
    payload: RegisterRequest,
    _: Annotated[dict[str, Any], Depends(require_admin)],
) -> dict[str, Any]:
    user = insert_user(payload)
    return {"user": user.model_dump()}


@app.post("/api/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest) -> AuthResponse:
    jwt_secret()
    try:
        document = users_collection().find_one({"email": payload.email})
    except PyMongoError as error:
        logger.exception("Could not look up user for login")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication database is unavailable",
        ) from error

    if not document or not password_hash.verify(payload.password, document["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user = public_user(document)
    return AuthResponse(token=issue_token(user), user=user)


@app.patch("/api/auth/fcm-token")
def save_fcm_token(payload: FcmTokenRequest, user: Annotated[dict[str, Any], Depends(require_auth)]) -> dict[str, bool]:
    try:
        result = users_collection().update_one(
            {"_id": mongo_id(user["id"])},
            {"$set": {"fcm_token": payload.fcm_token, "updated_at": datetime.now(timezone.utc)}},
        )
    except PyMongoError as error:
        logger.exception("Could not save FCM token")
        raise HTTPException(status_code=503, detail="Database is unavailable") from error
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.get("/api/services")
def get_services() -> list[dict[str, Any]]:
    try:
        services = collection("services").find({"active": {"$ne": False}}).sort("name", 1)
        result = []
        for item in services:
            service = {
                "id": str(item["_id"]),
                "name": item["name"],
                "description": item.get("description", ""),
                "image_url": item.get("image_url"),
            }
            if "sub_services" in item:
                service["sub_services"] = item["sub_services"]
            result.append(service)
        return result
    except PyMongoError as error:
        logger.exception("Could not list services")
        raise HTTPException(status_code=503, detail="Service catalog is unavailable") from error


@app.post("/api/services", status_code=status.HTTP_201_CREATED)
def create_service(
    payload: ServiceCreateRequest,
    _: Annotated[dict[str, Any], Depends(require_admin)],
) -> dict[str, Any]:
    document = {
        "name": payload.name,
        "description": payload.description.strip(),
        "image_url": payload.image_url,
        "sub_services": [item.model_dump() for item in payload.sub_services],
        "active": True,
        "created_at": datetime.now(timezone.utc),
    }
    try:
        result = collection("services").insert_one(document)
    except PyMongoError as error:
        logger.exception("Could not create service")
        raise HTTPException(status_code=503, detail="Service catalog is unavailable") from error

    document["_id"] = result.inserted_id
    document.pop("active")
    document.pop("created_at")
    document["id"] = str(document.pop("_id"))
    return document


@app.post("/api/requests")
def create_request(
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.consumer))],
    service_id: Annotated[str, Form()],
    address: Annotated[str, Form(min_length=1, max_length=1000)],
    notes: Annotated[str, Form(max_length=5000)] = "",
    lat: Annotated[float | None, Form()] = None,
    lng: Annotated[float | None, Form()] = None,
    prescription: Annotated[UploadFile | None, File()] = None,
) -> dict[str, Any]:
    address = address.strip()
    if not address:
        raise HTTPException(status_code=422, detail="Address must not be blank")
    service_object_id = mongo_id(service_id)
    try:
        service = collection("services").find_one({"_id": service_object_id, "active": {"$ne": False}})
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
        user_document = users_collection().find_one({"_id": mongo_id(user["id"])})
        if not user_document:
            raise HTTPException(status_code=404, detail="User not found")
        now = datetime.now(timezone.utc)
        request_id = str(ObjectId())
        prescription_key = attach_prescription(prescription, request_id, user["id"]) if prescription else None
        document = {
            "_id": ObjectId(request_id),
            "service_id": service_object_id,
            "service_name": service["name"],
            "description": service.get("description", ""),
            "image_url": service.get("image_url"),
            "consumer_id": mongo_id(user["id"]),
            "consumer_name": user_document["name"],
            "consumer_phone": user_document.get("phone"),
            "address": address,
            "notes": notes.strip(),
            "lat": lat,
            "lng": lng,
            "status": RequestStatus.pending_approval.value,
            "status_history": [{"status": RequestStatus.pending_approval.value, "at": now, "note": "Request submitted"}],
            "created_at": now,
        }
        if prescription_key:
            document["prescription_key"] = prescription_key
        collection("requests").insert_one(document)
        return request_view(document)
    except HTTPException:
        raise
    except PyMongoError as error:
        logger.exception("Could not create service request")
        raise HTTPException(status_code=503, detail="Request could not be saved") from error


@app.get("/api/requests/mine")
def get_my_requests(user: Annotated[dict[str, Any], Depends(require_role(UserRole.consumer))]) -> list[dict[str, Any]]:
    try:
        documents = collection("requests").find({"consumer_id": mongo_id(user["id"])}).sort("created_at", -1)
        return [request_view(item) for item in documents]
    except PyMongoError as error:
        logger.exception("Could not list consumer requests")
        raise HTTPException(status_code=503, detail="Requests are unavailable") from error


@app.get("/api/requests/{request_id}")
def get_request(
    request_id: str,
    user: Annotated[dict[str, Any], Depends(require_auth)],
) -> dict[str, Any]:
    query = {"_id": mongo_id(request_id)}
    if user["role"] == UserRole.consumer.value:
        query["consumer_id"] = mongo_id(user["id"])
    else:
        query["provider_id"] = mongo_id(user["id"])
    try:
        document = collection("requests").find_one(query)
    except PyMongoError as error:
        logger.exception("Could not load service request")
        raise HTTPException(status_code=503, detail="Request is unavailable") from error
    if not document:
        raise HTTPException(status_code=404, detail="Request not found")
    return request_view(document)


@app.patch("/api/requests/{request_id}/cancel")
def cancel_request(
    request_id: str,
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.consumer))],
) -> dict[str, Any]:
    request_object_id = mongo_id(request_id)
    try:
        document = collection("requests").find_one(
            {"_id": request_object_id, "consumer_id": mongo_id(user["id"])}
        )
        if not document:
            raise HTTPException(status_code=404, detail="Request not found")
        if document["status"] not in {
            RequestStatus.pending_approval.value,
            RequestStatus.approved.value,
            RequestStatus.notified.value,
            RequestStatus.quoted.value,
        }:
            raise HTTPException(status_code=409, detail="This request can no longer be cancelled")
        now = datetime.now(timezone.utc)
        collection("requests").update_one(
            {"_id": request_object_id},
            {
                "$set": {"status": RequestStatus.cancelled.value, "updated_at": now},
                "$push": {"status_history": {"status": RequestStatus.cancelled.value, "at": now, "note": "Cancelled by consumer"}},
            },
        )
        return request_view(collection("requests").find_one({"_id": request_object_id}))
    except HTTPException:
        raise
    except PyMongoError as error:
        logger.exception("Could not cancel request")
        raise HTTPException(status_code=503, detail="Request could not be cancelled") from error


@app.get("/api/providers/me/requests")
def get_provider_requests(user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))]) -> list[dict[str, Any]]:
    try:
        documents = collection("requests").find(
            {"provider_id": mongo_id(user["id"]), "status": {"$in": ["awarded", "scheduled", "completed"]}}
        ).sort("created_at", -1)
        return [request_view(item) for item in documents]
    except PyMongoError as error:
        logger.exception("Could not list provider bookings")
        raise HTTPException(status_code=503, detail="Bookings are unavailable") from error


@app.get("/api/providers/me/available")
def get_available_requests(user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))]) -> list[dict[str, Any]]:
    try:
        provider_id = mongo_id(user["id"])
        profile = users_collection().find_one({"_id": provider_id}) or {}
        if not profile.get("available", True):
            return []
        requests = collection("requests").find(
            {"status": {"$in": [RequestStatus.notified.value, RequestStatus.quoted.value]}}
        ).sort("created_at", -1)
        provider_quotes = {
            str(item["request_id"])
            for item in collection("quotes").find({"provider_id": provider_id}, {"request_id": 1})
        }
        results = []
        for document in requests:
            item = request_view(document)
            item["already_quoted"] = str(document["_id"]) in provider_quotes
            results.append(item)
        return results
    except PyMongoError as error:
        logger.exception("Could not list available requests")
        raise HTTPException(status_code=503, detail="Available requests are unavailable") from error


@app.post("/api/quotes")
def submit_quote(
    payload: QuoteRequest,
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))],
) -> dict[str, Any]:
    request_object_id = mongo_id(payload.request_id)
    provider_id = mongo_id(user["id"])
    requests = collection("requests")
    quotes = collection("quotes")
    try:
        request = requests.find_one(
            {"_id": request_object_id, "status": {"$in": [RequestStatus.notified.value, RequestStatus.quoted.value]}}
        )
        if not request:
            raise HTTPException(status_code=404, detail="Request is not open for quotes")
        quotes.create_index([("request_id", 1), ("provider_id", 1)], unique=True)
        quote = {
            "request_id": request_object_id,
            "provider_id": provider_id,
            "provider_name": "",
            "amount": payload.amount,
            "note": payload.note.strip(),
            "status": "pending",
            "created_at": datetime.now(timezone.utc),
        }
        provider = users_collection().find_one({"_id": provider_id}) or {}
        quote["provider_name"] = provider.get("name", "")
        result = quotes.insert_one(quote)
        add_notification(
            request["consumer_id"],
            "New provider quote",
            f"A provider submitted a quote for {request['service_name']}.",
        )
        requests.update_one(
            {"_id": request_object_id, "status": {"$in": [RequestStatus.notified.value, RequestStatus.quoted.value]}},
            {
                "$set": {"status": RequestStatus.quoted.value, "updated_at": datetime.now(timezone.utc)},
                "$push": {"status_history": {"status": RequestStatus.quoted.value, "at": datetime.now(timezone.utc), "note": "Provider submitted a quote"}},
            },
        )
        return {"id": str(result.inserted_id), "status": "pending"}
    except DuplicateKeyError as error:
        raise HTTPException(status_code=409, detail="You have already quoted on this request") from error
    except HTTPException:
        raise
    except PyMongoError as error:
        logger.exception("Could not submit provider quote")
        raise HTTPException(status_code=503, detail="Quote could not be submitted") from error


@app.get("/api/providers/me/profile")
def get_provider_profile(user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))]) -> dict[str, Any]:
    try:
        document = users_collection().find_one({"_id": mongo_id(user["id"])})
    except PyMongoError as error:
        logger.exception("Could not load provider profile")
        raise HTTPException(status_code=503, detail="Provider profile is unavailable") from error
    if not document:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"available": document.get("available", True)}


@app.put("/api/providers/me/profile")
def update_provider_profile(
    payload: ProviderProfileUpdate,
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))],
) -> dict[str, bool]:
    try:
        result = users_collection().update_one(
            {"_id": mongo_id(user["id"])},
            {"$set": {"available": payload.available, "updated_at": datetime.now(timezone.utc)}},
        )
    except PyMongoError as error:
        logger.exception("Could not update provider profile")
        raise HTTPException(status_code=503, detail="Provider profile could not be updated") from error
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"available": payload.available}


@app.get("/api/providers/me/stats")
def get_provider_stats(user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))]) -> dict[str, int | float]:
    provider_id = mongo_id(user["id"])
    try:
        quotes = list(collection("quotes").find({"provider_id": provider_id}))
        won_quotes = sum(1 for quote in quotes if quote.get("status") == "won")
        lost_quotes = sum(1 for quote in quotes if quote.get("status") == "lost")
        pending_quotes = sum(1 for quote in quotes if quote.get("status", "pending") == "pending")
        completed = list(
            collection("requests").find({"provider_id": provider_id, "status": RequestStatus.completed.value})
        )
        active = collection("requests").count_documents(
            {"provider_id": provider_id, "status": {"$in": ["awarded", "scheduled"]}}
        )
        return {
            "earned": sum(float(item.get("final_price") or 0) for item in completed),
            "fulfilled": len(completed),
            "active": active,
            "quotes_won": won_quotes,
            "quotes_lost": lost_quotes,
            "quotes_pending": pending_quotes,
        }
    except PyMongoError as error:
        logger.exception("Could not calculate provider statistics")
        raise HTTPException(status_code=503, detail="Provider statistics are unavailable") from error


@app.patch("/api/requests/{request_id}/schedule")
def schedule_request(
    request_id: str,
    payload: ScheduleRequest,
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))],
) -> dict[str, Any]:
    request_object_id = mongo_id(request_id)
    provider_id = mongo_id(user["id"])
    scheduled_at = payload.scheduled_at
    if scheduled_at.tzinfo is None:
        raise HTTPException(status_code=422, detail="scheduled_at must include a timezone")
    if scheduled_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="scheduled_at must be in the future")
    try:
        requests = collection("requests")
        document = requests.find_one(
            {"_id": request_object_id, "provider_id": provider_id, "status": RequestStatus.awarded.value}
        )
        if not document:
            raise HTTPException(status_code=404, detail="Awarded booking not found")
        now = datetime.now(timezone.utc)
        requests.update_one(
            {"_id": request_object_id},
            {
                "$set": {"scheduled_at": scheduled_at, "status": RequestStatus.scheduled.value, "updated_at": now},
                "$push": {"status_history": {"status": RequestStatus.scheduled.value, "at": now, "note": "Provider scheduled the service"}},
            },
        )
        add_notification(document["consumer_id"], "Service scheduled", f"{document['service_name']} has been scheduled.")
        return request_view(requests.find_one({"_id": request_object_id}))
    except HTTPException:
        raise
    except PyMongoError as error:
        logger.exception("Could not schedule service")
        raise HTTPException(status_code=503, detail="Service could not be scheduled") from error


@app.patch("/api/requests/{request_id}/complete")
def complete_request(
    request_id: str,
    user: Annotated[dict[str, Any], Depends(require_role(UserRole.provider))],
) -> dict[str, Any]:
    request_object_id = mongo_id(request_id)
    provider_id = mongo_id(user["id"])
    try:
        requests = collection("requests")
        document = requests.find_one(
            {"_id": request_object_id, "provider_id": provider_id, "status": RequestStatus.scheduled.value}
        )
        if not document:
            raise HTTPException(status_code=404, detail="Scheduled booking not found")
        now = datetime.now(timezone.utc)
        requests.update_one(
            {"_id": request_object_id},
            {
                "$set": {"status": RequestStatus.completed.value, "updated_at": now},
                "$push": {"status_history": {"status": RequestStatus.completed.value, "at": now, "note": "Provider marked the service complete"}},
            },
        )
        add_notification(document["consumer_id"], "Service completed", f"{document['service_name']} has been marked complete.")
        return request_view(requests.find_one({"_id": request_object_id}))
    except HTTPException:
        raise
    except PyMongoError as error:
        logger.exception("Could not complete service")
        raise HTTPException(status_code=503, detail="Service could not be completed") from error


@app.get("/api/notifications/mine")
def get_my_notifications(user: Annotated[dict[str, Any], Depends(require_auth)]) -> list[dict[str, Any]]:
    try:
        documents = collection("notifications").find({"user_id": mongo_id(user["id"])}).sort("created_at", -1).limit(100)
        return [notification_view(item) for item in documents]
    except PyMongoError as error:
        logger.exception("Could not list notifications")
        raise HTTPException(status_code=503, detail="Notifications are unavailable") from error


@app.patch("/api/notifications/read-all")
def mark_notifications_read(user: Annotated[dict[str, Any], Depends(require_auth)]) -> dict[str, int]:
    try:
        result = collection("notifications").update_many(
            {"user_id": mongo_id(user["id"]), "read": {"$ne": True}},
            {"$set": {"read": True}},
        )
        return {"modified": result.modified_count}
    except PyMongoError as error:
        logger.exception("Could not mark notifications as read")
        raise HTTPException(status_code=503, detail="Notifications could not be updated") from error


@app.patch("/api/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    user: Annotated[dict[str, Any], Depends(require_auth)],
) -> dict[str, bool]:
    try:
        result = collection("notifications").update_one(
            {"_id": mongo_id(notification_id), "user_id": mongo_id(user["id"])},
            {"$set": {"read": True}},
        )
    except PyMongoError as error:
        logger.exception("Could not mark notification as read")
        raise HTTPException(status_code=503, detail="Notification could not be updated") from error
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"read": True}
