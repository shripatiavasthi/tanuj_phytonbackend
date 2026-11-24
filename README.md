# CareConnect API

FastAPI backend for Vercel, with MongoDB-backed authentication and the routes currently called by the consumer and provider mobile apps.

## Routes

- `GET /` — service metadata
- `GET /api/health` — health check
- `POST /api/auth/register` — create a consumer or provider account
- `POST /api/auth/login` — authenticate and return a 24-hour JWT
- `POST /api/admin/setup` — create the one-time CRM admin account (requires `X-Admin-Setup-Secret`)
- `POST /api/admin/login` — authenticate a CRM admin and return a 12-hour JWT
- `POST /api/admin/users` — create a consumer/provider account (requires admin JWT)
- `PATCH /api/auth/fcm-token` — save the signed-in user's FCM device token
- `GET /api/services` — list active services and subservices from MongoDB's `services` collection
- `POST /api/services` — create a service and its optional subservices (requires admin JWT)
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

2. Set `MONGODB_URI` in `.env` to your MongoDB connection string, replace `JWT_SECRET` with a random value of at least 32 characters, and set `CRM_ADMIN_SETUP_SECRET` to a separate random secret of at least 32 characters. Generate secrets with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. The app loads `.env` automatically for local development; never commit it.
3. Run:

   ```sh
   uvicorn app:app --reload
   ```

## Deploy to Vercel

Import this folder as the Vercel project root and add `MONGODB_URI`, `MONGODB_DATABASE`, `JWT_SECRET`, and `CRM_ADMIN_SETUP_SECRET` in the Vercel project's Environment Variables for the environments you use. Use separate random secrets of at least 32 characters. Add `S3_BUCKET`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` if prescription uploads are needed. Do not commit credentials. Vercel detects the FastAPI `app` instance and dependencies from `requirements.txt`.

The mobile app API base URL should point to the deployed domain with the `/api` suffix.

## CRM service catalog

Set a long, random `CRM_ADMIN_SETUP_SECRET` in the backend environment before deployment. Open the CRM and choose **First time? Set up the first admin**; enter the setup secret and create the administrator's email/password. The endpoint can only create the singleton admin once. After initial setup, remove `CRM_ADMIN_SETUP_SECRET` from the backend environment and redeploy to disable further setup attempts. Admin passwords are hashed in MongoDB's `admins` collection. The CRM signs in through `/api/admin/login` and retains its 12-hour JWT only in the current browser session.

`POST /api/services` accepts a service `name`, optional `description`, optional `image_url` as a base64 data URL, and an optional `sub_services` array (`name`, optional `description`, optional `icon`, optional `image_url`). It requires a valid admin JWT. Images are limited to 5 MB and JPEG, PNG, or WebP. Image data is stored in MongoDB in the `image_url` field of its service or subservice and returned through `GET /api/services`; subservices are stored in `sub_services`.
# tanuj_phytonbackend
