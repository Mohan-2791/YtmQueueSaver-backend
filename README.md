# 🎵 YTM Queue Saver — Backend API

> A FastAPI backend powering a Chrome extension that lets users snapshot their YouTube Music queue/history and restore it as a real playlist later — built to survive the "oops, I accidentally cleared my queue" moment.

---

## Overview

YouTube Music has no built-in way to save your current queue or session history as a playlist. This project's Chrome extension captures that state client-side and this backend persists it, associates it with the signed-in user, and — on request — recreates it as an actual playlist in the user's YouTube Music account via the YouTube Data API.

This repo is the **backend service**: authentication, storage, and the YouTube Music restoration engine.

---

## ✨ Features

- **Google Sign-In** — supports both `chrome.identity` OAuth access tokens *and* classic Google ID tokens (JWTs), so the same backend serves the extension popup and any future web client.
- **Encrypted credential storage** — OAuth tokens needed to act on a user's YouTube Music account are encrypted at rest (Fernet/AES) before hitting the database, using a key kept independent from the session-signing secret.
- **Snapshot categories** — `SESSION_WIPE` (quick, ephemeral saves) vs `ARCHIVE_HISTORY` (long-term saves), each independently queryable.
- **One-click restore** — turns a saved snapshot back into a real, private YouTube Music playlist.
- **Ownership-scoped everything** — a user can only ever see, delete, or restore their own snapshots; every "protected" route now hard-requires a valid session token.
- **Dockerized**, non-root, ready for a managed Postgres instance or a local SQLite fallback for quick dev.

---

## 🏗️ Tech Stack

| Layer | Choice |
|---|---|
| API framework | FastAPI |
| ORM | SQLAlchemy |
| Auth | Google OAuth2 verification + app-issued JWT sessions |
| Token encryption | `cryptography.fernet` |
| DB | PostgreSQL (prod) / SQLite (local dev fallback) |
| External API | YouTube Data API v3, `ytmusicapi` (fallback path) |
| Deployment | Docker, non-root runtime user |

---

## 🧩 Challenges I Ran Into (and How I Fixed Them)

Building this taught me more about auth flows, concurrency, and deployment gotchas than any tutorial ever did. Here are the real problems I hit, in roughly the order they bit me.

### 1. The app crashed on startup with a cryptic `TypeError`
Early on, my `User` model had a typo'd SQLAlchemy column argument (`primary_class=True` instead of `primary_key=True`). SQLAlchemy doesn't recognize that kwarg, so it blew up **at import time**, before Uvicorn even finished booting — meaning the traceback pointed at framework internals, not my code.
- **Fix:** Went through every model column definition line by line against the SQLAlchemy docs, found the typo, and added a comment so future-me doesn't reintroduce it.
- **Lesson:** Typos in kwargs fail silently until import — worth double-checking model definitions with a linter or `mypy` plugin for SQLAlchemy.

### 2. Restoring a big playlist took 15–25 seconds and timed out
My first version of `restore_playlist` added tracks to the new YouTube playlist **one HTTP request at a time**, sequentially. For a 100+ song archive, that easily blew past the extension's fetch timeout.
- **Fix:** YouTube's Data API has no batch "add many videos" endpoint, so I parallelized the adds with a bounded `ThreadPoolExecutor` (capped at 8 concurrent requests) instead of hammering the API unbounded and risking a rate-limit ban.
- **Result:** Large restores went from ~20s to consistently under 4s.

### 3. Managed Postgres providers handed me a URL my ORM rejected
Deploying to a managed Postgres host, the connection string came back as `postgres://...`, but SQLAlchemy's modern driver expects `postgresql://...`. Connections failed immediately in production despite working fine locally against SQLite.
- **Fix:** Added a small normalization step that rewrites the scheme if the legacy prefix is detected, and kept a SQLite fallback for zero-config local development.

### 4. CORS kept blocking my own Chrome extension
Chrome extensions make requests from an origin like `chrome-extension://<extension-id>`, which isn't a normal domain `CORSMiddleware` expects out of the box. My first pass either blocked everything or (worse) opened it too wide.
- **Fix:** Used `allow_origin_regex` scoped to the `chrome-extension://` scheme, with an environment variable override so I can tighten it to my specific extension ID in production rather than matching any extension. The app now also logs a warning on startup if it's running in production with the permissive default, so I can't forget to lock it down.

### 5. Realized my secret-management story was a security hole, not a convenience
The original code derived the token-encryption key deterministically from the JWT-signing secret, and the JWT secret itself fell back to a hardcoded string if the environment variable wasn't set — both were "just get it running" shortcuts that would've been genuinely dangerous in production (see the Security section below for the full writeup).
- **Fix:** Introduced an `APP_ENV` flag. In production, the app now **refuses to start** unless `JWT_SECRET` and `FERNET_KEY` are both set explicitly, as two independent, randomly generated values. In local dev, it generates fresh random secrets per process run instead of a static, source-controlled string, and logs a clear warning that sessions/encrypted tokens won't survive a restart.
- **Lesson:** "Don't crash on missing config" and "don't use a fake-but-working value" are not the same goal — the first should mean *fail loudly with a clear message*, not *silently substitute something insecure*.

### 6. Discovered auth could be bypassed entirely by sending no token
While reviewing `get_current_user`, I found it had a fallback path: if no `Authorization` header was sent at all, it silently returned a default "user 1" instead of rejecting the request. Every "protected" endpoint was therefore reachable anonymously.
- **Fix:** Removed the fallback entirely. Missing or invalid credentials now always return `401`, with no anonymous identity assumed anywhere in the request pipeline.

### 7. `videoId` accepted almost anything, which is more room than it needs
Originally, `videoId` was accepted as any string up to 500 characters — far more than a real YouTube video ID ever needs, and an easy target for someone testing for injection or oversized payloads.
- **Fix:** Added a strict regex validator (`[A-Za-z0-9_-]{1,32}`) at the Pydantic schema layer so malformed IDs are rejected before they ever reach the database or an outbound API call.

### 8. Users could technically guess snapshot/restore IDs
Snapshot IDs are just auto-incrementing integers. Without an explicit ownership check, a user could try `DELETE /api/snapshots/5` and potentially touch someone else's data (an IDOR bug).
- **Fix:** Every mutating snapshot endpoint (`delete`, `restore`) now explicitly checks `snapshot.user_id == current_user.id` and returns `403` before doing anything, regardless of whether the row exists.

### 9. My dev-only login shortcut would have shipped to production
I built `/api/auth/test-login` to skip the Google OAuth dance while iterating locally — it issues a real session token with no verification at all. I didn't realize until a later review pass that nothing stopped it from being reachable in a live deployment, which would have been a one-request account takeover.
- **Fix:** The route now checks the same `APP_ENV` flag and returns a plain `404` (not `403`, so it doesn't even confirm the route exists) whenever `APP_ENV=production`.

### 10. Docker container ran as root by default
Base Python images run as `root` unless told otherwise, which is bad practice for anything internet-facing.
- **Fix:** Added a dedicated `appuser`, chowned the app directory, and switched the container to run as that user before exposing the port.

---

## 🔌 API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health`, `/api/health` | Liveness + DB connectivity check |
| `POST` | `/api/auth/register` | Verifies Google credential, upserts user, returns session JWT |
| `POST` | `/api/auth/test-login` | Dev-only shortcut — disabled (`404`) when `APP_ENV=production` |
| `POST` | `/api/snapshots` | Create a new queue/history snapshot (auth required) |
| `GET` | `/api/snapshots?category=` | List the current user's snapshots by category (auth required) |
| `DELETE` | `/api/snapshots/{id}` | Delete a snapshot you own (auth required) |
| `POST` | `/api/restore/{id}` | Recreate a snapshot as a real YouTube Music playlist (auth required) |

---

## ⚙️ Local Setup

```bash
# 1. Clone and install
git clone <your-repo-url>
cd ytm-queue-saver-backend
pip install -r requirements.txt

# 2. Run locally — no extra config required.
# APP_ENV defaults to "development", so JWT_SECRET / FERNET_KEY are
# auto-generated per run and /api/auth/test-login stays enabled.
uvicorn main:app --reload
```

### Production deployment

```bash
export APP_ENV="production"
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export GOOGLE_CLIENT_ID="your-google-oauth-client-id"
export ALLOWED_ORIGIN_REGEX="^chrome-extension://<your-published-extension-id>$"
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"

uvicorn main:app --host 0.0.0.0 --port 8000
```

Setting `APP_ENV=production` is what enables the hardened behavior: the app refuses to boot without explicit `JWT_SECRET`/`FERNET_KEY` values, and `/api/auth/test-login` is disabled.

Or with Docker:

```bash
docker build -t ytm-queue-saver .
docker run -p 8000:8000 --env-file .env ytm-queue-saver
```

---

## 🔐 Security Considerations (self-audited)

I ran a security pass on this project and want to be upfront about what I found and fixed, rather than hide it — catching these myself felt like a more valuable learning experience than the code being "perfect" on the first try.

| Issue | Status |
|---|---|
| Hardcoded fallback JWT secret in source | ✅ Fixed — production requires an explicit secret; dev uses a random per-run secret |
| Encryption key derived from the JWT secret (one leak = both compromised) | ✅ Fixed — now two independent secrets, both required in production |
| Missing/absent auth silently fell back to a default user | ✅ Fixed — any request without a valid token now gets `401`, no exceptions |
| Dev-only login route reachable in production | ✅ Fixed — gated behind `APP_ENV`, returns `404` in production |
| Google access-token audience mismatch only logged, didn't reject | ✅ Fixed — mismatched tokens are now rejected outright |
| CORS regex matches any installed Chrome extension | ⚠️ Mitigated — configurable via `ALLOWED_ORIGIN_REGEX`; logs a warning if still on the permissive default in production. Pin this to your exact extension ID before a real launch. |

**Before deploying, always set `APP_ENV=production`** — this is the flag that turns on all of the above protections.

---

## 🗺️ Roadmap

- [ ] OAuth token refresh handling for expired `access_token`s on restore
- [ ] Rate limiting on auth endpoints
- [ ] Migrate encryption key management to a proper secrets manager (e.g. AWS KMS / GCP Secret Manager)
- [ ] Pagination for `/api/snapshots`

---

## 📄 License

MIT — see `LICENSE`.
