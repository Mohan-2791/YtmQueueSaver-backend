# YTM Queue Saver: Backend API

A FastAPI service that stores users' YouTube Music queue snapshots and restores them as real playlists through the YouTube Data API v3. It is the backend for a published Chrome extension.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Tests](https://github.com/Mohan-2791/YtmQueueSaver-backend/actions/workflows/tests.yml/badge.svg)

---

## Overview

YouTube Music cannot save the current queue. If it is cleared by accident, it is gone. The Chrome extension captures the queue in the browser and sends it to this service, which:

1. **Authenticates** the user with their Google account and issues a signed session token.
2. **Stores** each queue as a snapshot, scoped to its owner and filed under a category (`SESSION_WIPE` for quick saves, `ARCHIVE_HISTORY` for long-term ones).
3. **Restores** a snapshot on request by creating a private playlist in the user's YouTube Music account, using the OAuth token the user granted.

The restore step is the hard part. The YouTube Data API allows 10,000 quota units per day for the whole project, and writing a single track costs 50. A naive implementation exhausts the daily allowance on the first large restore. Most of the engineering in this project is about making restores cheap, safe, and compatible with a client that cannot be changed overnight.

## Key Characteristics

| Area | Approach |
|---|---|
| **Quota** | Playlist caching, a local mirror of playlist contents, and a per-user and global circuit breaker. A repeat restore of a 100-track snapshot dropped from 5,050 units to 0. |
| **Credential storage** | OAuth tokens encrypted with AES-256-GCM envelope encryption. The owner's user ID is bound in as authenticated data, and master keys rotate without downtime. |
| **Sessions** | RS256-signed JWTs with a pinned algorithm, issuer and audience checks, and server-side revocation on logout. |
| **Compatibility** | The API contract with the published extension is frozen. A test suite replays the extension's real requests and asserts the exact responses. |
| **Data ownership** | Every snapshot route verifies ownership. `DELETE /api/account` revokes the Google token and removes all of a user's data. |
| **Testing** | 79 tests that run with no network access and spend no YouTube quota. |

## Architecture

```mermaid
flowchart LR
    EXT["Chrome extension"] -->|"Bearer JWT"| API["FastAPI app"]
    API --> MW["Middleware: CORS allowlist, security headers, rate limits, body caps"]
    MW --> AUTH["auth.py: Google verification, JWT issue and revoke"]
    MW --> SVC["ytm_service.py: restore engine"]
    SVC --> QT["quota.py: usage ledger and circuit breaker"]
    SVC --> CR["crypto.py: AES-256-GCM envelope"]
    SVC --> YT[("YouTube Data API v3")]
    AUTH --> DB[("PostgreSQL or SQLite")]
    QT --> DB
    CR --> DB
```

More detail, including the restore flow and data model, is in [docs/architecture.md](docs/architecture.md).

## Engineering Notes

Each of these is a problem that came up during development, with the reasoning behind the solution. Start with the first if you only read one.

| Document | What it covers |
|---|---|
| [Quota optimization](docs/quota-optimization.md) | Auditing a 10,000-unit daily budget, cutting a restore from 5,050 units to 0, and why parallel inserts were removed. |
| [Security hardening](docs/security-hardening.md) | Token encryption, asymmetric sessions, ownership checks, and the findings from a self-audit. |
| [Engineering challenges](docs/engineering-challenges.md) | Twelve concrete bugs and design problems, each with cause, fix, and lesson. |
| [Hardening reference](HARDENING.md) | Item-by-item table of every control, classified by whether it needs an extension release. |

## API

| Method | Path | Auth | Description |
|---|---|:---:|---|
| `GET` | `/health`, `/api/health` | No | Liveness and database check |
| `POST` | `/api/auth/register` | No | Verify Google credential, upsert user, return session JWT |
| `POST` | `/api/auth/test-login` | No | Development only; returns `404` in production |
| `POST` | `/api/auth/logout` | Yes | Revoke the current session |
| `POST` | `/api/snapshots` | Yes | Save a queue snapshot |
| `GET` | `/api/snapshots?category=` | Yes | List the caller's snapshots |
| `DELETE` | `/api/snapshots/{id}` | Yes | Delete a snapshot the caller owns |
| `POST` | `/api/restore/{id}` | Yes | Recreate a snapshot as a YouTube Music playlist |
| `DELETE` | `/api/account` | Yes | Revoke the Google token and delete all user data |

A successful restore returns:

```json
{
  "status": "success",
  "ytm_playlist_id": "PL...",
  "playlist_url": "https://music.youtube.com/playlist?list=PL..."
}
```

Errors: `401` invalid or missing token, `403` snapshot belongs to another user, `404` snapshot not found, `502` restore failed or the quota budget was reached.

## Getting Started

```bash
git clone https://github.com/Mohan-2791/YtmQueueSaver-backend.git
cd YtmQueueSaver-backend
pip install -r requirements.txt -r requirements-dev.txt

uvicorn main:app --reload
```

With no configuration the app runs in development mode: SQLite storage, per-run generated keys (sessions do not survive a restart), and interactive docs at `http://localhost:8000/docs`. Copy `.env.example` to `.env` to customize settings.

### Tests

```bash
python -m pytest tests -q
python -m pyflakes *.py tests/*.py
```

The suite uses a throwaway SQLite database and replaces all outbound HTTP calls with an in-memory fake, so it needs no credentials and consumes no quota.

### Production

With `APP_ENV=production` the application refuses to start unless every secret is set explicitly.

```bash
export APP_ENV="production"
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
export YTM_CLIENT_ID="<google-oauth-client-id>"
export ALLOWED_ORIGINS="chrome-extension://<extension-id>"
export KMS_MASTER_KEY="$(python -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
export JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
```

Production mode also disables the test login route and Swagger UI, enables HSTS and a strict CSP, and turns off the `ytmusicapi` fallback, which bypasses quota accounting.

```bash
docker build -t ytm-queue-saver .
docker run -p 8000:8000 --env-file .env ytm-queue-saver
```

To rotate the master key, set `KMS_MASTER_KEY_ID` and move the previous key into `KMS_MASTER_KEY_PREVIOUS`. Existing records stay readable and are re-wrapped on next access.

## Project Structure

```
main.py            Routes, middleware, error handling, rate limits
auth.py            Google token verification, RS256 sessions, revocation
crypto.py          AES-256-GCM envelope encryption and key rotation
ytm_service.py     Restore engine: caching, deduplication, retries
quota.py           Usage ledger, circuit breaker, Pacific-day accounting
models.py          SQLAlchemy models
schemas.py         Strict Pydantic request and response schemas
migrations.py      Additive, idempotent migrations applied at startup
config.py          Environment-driven settings; fails fast in production
audit.py           Structured audit log with token redaction
tests/             Contract, quota and security tests
docs/              Design notes and engineering write-ups
```

## Known Limitations and Roadmap

Some improvements cannot be made from the backend alone because the published extension fixes the contract. These are documented rather than worked around.

- **Partial restores are silent.** When a snapshot exceeds a user's daily budget, the restore completes as far as the budget allows and returns `200`. The response format has no field for dropped tracks. See [quota optimization](docs/quota-optimization.md#cap-versus-capability).
- **PKCE and `state` validation** require an extension release that performs the code exchange.
- **Server-side token refresh** requires the extension to send `refresh_token`, `scope` and `expiry`.
- **External secrets manager** (AWS KMS or GCP Secret Manager) to replace environment variables.
- **Pagination** for `GET /api/snapshots`.

## License

MIT. See `LICENSE`.
