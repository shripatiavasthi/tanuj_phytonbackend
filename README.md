# CareConnect API

FastAPI backend for Vercel, with MongoDB-backed authentication and the routes currently called by the consumer and provider mobile apps.

## Routes

- `GET /` — service metadata
- `GET /api/health` — health check
- `POST /api/auth/register` — create a consumer or provider account
- `POST /api/auth/login` — authenticate and return a 24-hour JWT
- `PATCH /api/auth/fcm-token` — save the signed-in user's FCM device token
- `GET /api/services` — list active services from MongoDB's `services` collection
- `POST /api/requests`, `GET /api/requests/mine`, `GET /api/requests/{id}`, `PATCH /api/requests/{id}/cancel`
- `GET /api/providers/me/requests`, `/available`, `/profile`, `/stats`; `PUT /api/providers/me/profile`
- `POST /api/quotes`
- `PATCH /api/requests/{id}/schedule`, `PATCH /api/requests/{id}/complete`
- `GET /api/notifications/mine`, `PATCH /api/notifications/read-all`, `PATCH /api/notifications/{id}/read`

Registration accepts `name`, `email`, `password`, optional `phone`, and an optional `role` (`consumer` or `provider`, default `consumer`). Responses match the mobile apps' `{ "token": "...", "user": { "id", "name", "email", "role", "phone" } }` contract. Passwords are stored as Argon2 hashes; email uniqueness is enforced by a MongoDB unique index.

Service requests start as `pending_approval`; providers see requests after an administrator changes their status to `notified`. The provider app submits quotes, but selecting a winning quote is an admin action and is not exposed by either mobile app. The backend expects service documents in `services`, user records in `users`, and creates `requests`, `quotes`, and `notifications` as needed. Prescription uploads require `S3_BUCKET` and AWS credentials in the environment; attachments are limited to 10 MB and common image/PDF types. FCM device tokens are stored, but sending push notifications is not implemented yet; notification feed entries are persisted in MongoDB.

## Local development

1. Create a virtual environment and install dependencies:

   ```sh
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Set `MONGODB_URI` in `.env` to your MongoDB connection string and replace `JWT_SECRET` with a random value of at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. The app loads `.env` automatically for local development; never commit it.
3. Run:

   ```sh
   uvicorn app:app --reload
   ```

## Deploy to Vercel

Import this folder as the Vercel project root and add `MONGODB_URI`, `MONGODB_DATABASE`, and `JWT_SECRET` in the Vercel project's Environment Variables for the environments you use. Set `JWT_SECRET` to a random value of at least 32 characters. Add `S3_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` if prescription uploads are needed. Do not commit credentials. Vercel detects the FastAPI `app` instance and dependencies from `requirements.txt`.

The mobile app API base URL should point to the deployed domain with the `/api` suffix.
# tanuj_phytonbackend
