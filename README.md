# 🎵 YTM Queue Saver — Backend API

> A FastAPI backend powering a Chrome extension that lets users snapshot their YouTube Music queue/history and restore it as a real playlist later — built to survive the "oops, I accidentally cleared my queue" moment.

---

## Overview

YouTube Music has no built-in way to save your current queue or session history as a playlist. This project's Chrome extension captures that state client-side and this backend persists it, associates it with the signed-in user, and — on request — recreates it as an actual playlist in the user's YouTube Music account via the YouTube Data API.

This repo is the **backend service**: authentication, storage, and the YouTube Music restoration engine.

---

## ✨ Features

- **Google Sign-In** — supports both `chrome.identity` OAuth access tokens *and* classic Google ID tokens (JWTs), so the same backend serves the extension popup and any future web client.
- **Encrypted credential storage** — OAuth tokens are encrypted at rest with AES-256-GCM envelope encryption (a fresh DEK per record, the owner's `user_id` bound in as AAD) before hitting the database, using a key kept independent from the session-signing key.
- **Quota-aware restore** — playlists are cached and reused, the local item mirror skips tracks already present, and a daily circuit breaker stops each request before spending past budget. A snapshot larger than the remaining budget is restored as far as the budget allows rather than refused whole. See [HARDENING.md](HARDENING.md).
- **Snapshot categories** — `SESSION_WIPE` (quick, ephemeral saves) vs `ARCHIVE_HISTORY` (long-term saves), each independently queryable.
- **One-click restore** — turns a saved snapshot back into a real, private YouTube Music playlist.
- **Ownership-scoped everything** — a user can only ever see, delete, or restore their own snapshots; every "protected" route now hard-requires a valid session token.
- **Revocable sessions & full deletion** — `POST /api/auth/logout` revokes the current session; `DELETE /api/account` revokes the Google token and cascades away every trace of the user's data.
- **Dockerized**, non-root, ready for a managed Postgres instance or a local SQLite fallback for quick dev.

---

## 🏗️ Tech Stack

| Layer | Choice |
|---|---|
| API framework | FastAPI |
| ORM | SQLAlchemy |
| Auth | Google OAuth2 verification + app-issued RS256 JWT sessions |
| Token encryption | AES-256-GCM envelope (`cryptography`) |
| Sessions | RS256 JWTs + a revocation table for logout |
| Quota accounting | Per-user, per-Pacific-day ledger with a circuit breaker |
| Rate limiting | slowapi, per-IP and per-user |
| DB | PostgreSQL (prod) / SQLite (local dev fallback) |
| Migrations | Additive, idempotent, applied on startup |
| External API | YouTube Data API v3, `ytmusicapi` (non-production fallback only) |
| Tests | pytest, 79 tests, no network |
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
- **First fix (later reversed):** YouTube's Data API has no batch "add many videos" endpoint, so I parallelized the adds with a bounded `ThreadPoolExecutor`.
- **Why it was reversed:** parallelism is what produced the `409 ABORTED / SERVICE_UNAVAILABLE` conflicts, and every retry of a conflicted insert costs another 50 units. Restores are sequential again, but the real fix was not concurrency at all — it was not making the calls. A restored playlist is now cached and reused, the local item mirror skips tracks already in it, and a repeat restore costs **zero** units instead of 5,050.
- **Lesson:** the slow path was a symptom. Optimizing the request rate while the request count stayed at N tracks × 50 units just burned the daily allowance faster.

### 3. Managed Postgres providers handed me a URL my ORM rejected
Deploying to a managed Postgres host, the connection string came back as `postgres://...`, but SQLAlchemy's modern driver expects `postgresql://...`. Connections failed immediately in production despite working fine locally against SQLite.
- **Fix:** Added a small normalization step that rewrites the scheme if the legacy prefix is detected, and kept a SQLite fallback for zero-config local development.

### 4. CORS kept blocking my own Chrome extension
Chrome extensions make requests from an origin like `chrome-extension://<extension-id>`, which isn't a normal domain `CORSMiddleware` expects out of the box. My first pass either blocked everything or (worse) opened it too wide with an `allow_origin_regex` matching any `chrome-extension://` origin — i.e. any installed extension.
- **Fix:** Replaced the permissive regex with an **exact-match allowlist** in `ALLOWED_ORIGINS`, pinned to the published extension ID `iegedaeoaampnaagmbfdefigjecepigo`. `ALLOWED_ORIGIN_REGEX` still exists for unusual deployments, but the list is the default and there is no wildcard fallback. Unknown origins are logged with a correlation ID rather than silently dropped.

### 5. Realized my secret-management story was a security hole, not a convenience
The original code derived the token-encryption key deterministically from the JWT-signing secret, and the JWT secret itself fell back to a hardcoded string if the environment variable wasn't set — both were "just get it running" shortcuts that would've been genuinely dangerous in production (see the Security section below for the full writeup).
- **Fix:** Introduced an `APP_ENV` flag. In production the app **refuses to start** unless `KMS_MASTER_KEY` and the `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY` pair are all set explicitly, and it no longer accepts a symmetric `JWT_SECRET` at all. In local dev it generates fresh random values per process run and logs a clear warning that sessions and encrypted tokens won't survive a restart.
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

### 11. The quota accounting was in the code but not in the request
Wiring a `QuotaTracker` into the service looked sufficient on paper. It wasn't: the tracker only saw calls made through the helper, so anything that bypassed that helper spent units the ledger never recorded — and a *retry* could slip past a budget that had already been checked once.
- **Fix:** Units are now reserved **inside** the request loop, so every attempt is charged before it is dispatched, and `ensure_budget` is checked before any network call. The three regression tests in `test_quota_and_security.py` exist specifically to pin this.

### 12. A `return` in the wrong place silently doubled my quota bill
`resolve_playlist` had `return` nested inside an `except` block. A *successful* database commit therefore fell through to creating a brand-new playlist, so every single restore created a second playlist and spent 50 units it did not need to. The API returned 200, so nothing looked wrong from the outside — only the quota ledger told the truth.
- **Fix:** Fixed the control flow, and added `test_warm_restore_spends_zero_units`, which asserts the second restore makes **no** YouTube call at all and adds zero units.
- **Lesson:** correct-looking code with a passing response is not the same as correct. The test that would have caught this asserts a *negative* — that something does **not** happen — which is the only way to pin a cost guarantee.

---

## 🔌 API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health`, `/api/health` | Liveness + DB connectivity check |
| `POST` | `/api/auth/register` | Verifies Google credential, upserts user, returns session JWT |
| `POST` | `/api/auth/test-login` | Dev-only shortcut — disabled (`404`) when `APP_ENV=production` |
| `POST` | `/api/auth/logout` | Revokes the current session token (`204`) |
| `POST` | `/api/snapshots` | Create a new queue/history snapshot (auth required) |
| `GET` | `/api/snapshots?category=` | List the current user's snapshots by category (auth required) |
| `DELETE` | `/api/snapshots/{id}` | Delete a snapshot you own (auth required) |
| `POST` | `/api/restore/{id}` | Recreate a snapshot as a real YouTube Music playlist (auth required) |
| `DELETE` | `/api/account` | Revoke the Google token and delete the account and all its data (`204`) |

Responses, status codes and error bodies are a **frozen contract** with the published extension. `tests/test_contract.py` replays the exact requests `extension/src/background/handlers.ts` makes and asserts the exact responses, so a change that would break the live client fails the suite.

---

## ⚙️ Local Setup

```bash
# 1. Clone and install
git clone https://github.com/Mohan-2791/YtmQueueSaver-backend.git
cd ytm-queue-saver-backend
pip install -r requirements.txt -r requirements-dev.txt

# 2. Run locally — no extra config required.
# APP_ENV defaults to "development", so keys are auto-generated per run and
# /api/auth/test-login stays enabled. Generated keys are ephemeral: tokens and
# sessions do not survive a restart.
uvicorn main:app --reload
```

For local work, copy the template and adjust as needed:

```bash
cp .env.example .env
```

### Tests

```bash
python -m pytest tests -q          # 79 tests
python -m pyflakes *.py tests/*.py # lint
```

The suite runs against a throwaway SQLite database with every outbound HTTP call replaced by an in-memory fake, so it consumes no YouTube quota and needs no credentials.

### Migrations

Migrations are additive and idempotent, and run automatically on startup. They only ever `ADD COLUMN` / `CREATE TABLE` / `CREATE INDEX`, so an existing database gains the new state without losing rows.

To roll back, run the `downgrade` statement for the highest migration ID you want removed — see the table in [HARDENING.md](HARDENING.md). Rolling back drops cached state (playlist cache, item mirror, quota ledger), never user snapshots or accounts.

### Production deployment

Every secret below is **required**: with `APP_ENV=production` the app refuses to boot if any is missing, rather than falling back to something insecure. `.env.example` documents all of them and includes the one-liners to generate the key material.

```bash
export APP_ENV="production"
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
export YTM_CLIENT_ID="your-google-oauth-client-id"          # must match the extension
export ALLOWED_ORIGINS="chrome-extension://iegedaeoaampnaagmbfdefigjecepigo"
export KMS_MASTER_KEY="$(python -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
# RS256 keypair - store both halves; neither is derivable from the other.
export JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
export JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."

uvicorn main:app --host 0.0.0.0 --port 8000
```

Setting `APP_ENV=production` also disables `/api/auth/test-login`, turns off Swagger UI and the OpenAPI schema, enables HSTS and CSP, and disables the `ytmusicapi` fallback (which creates a new playlist on every run and bypasses quota accounting).

> **Key rotation.** Set `KMS_MASTER_KEY_ID` and put the outgoing key in `KMS_MASTER_KEY_PREVIOUS` as `<id>:<base64 key>`. Existing rows stay readable and are re-wrapped on next access, so rotation needs no downtime and no bulk rewrite.

> **Note:** the old symmetric `JWT_SECRET` is no longer read. Migrating from the previous deployment invalidates existing sessions once; the extension re-authenticates silently on its next request.

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
| Hardcoded fallback JWT secret in source | ✅ Fixed — RS256 with an explicit keypair; production refuses to boot without it |
| Encryption key derived from the JWT secret (one leak = both compromised) | ✅ Fixed — independent keys, both required in production |
| Fernet without AAD (AES-128-CBC, token-swappable between rows) | ✅ Fixed — AES-256-GCM envelope with `user_id` bound in as AAD |
| Missing/absent auth silently fell back to a default user | ✅ Fixed — any request without a valid token now gets `401`, no exceptions |
| Dev-only login route reachable in production | ✅ Fixed — gated behind `APP_ENV`, returns `404` in production |
| Google access-token audience mismatch only logged, didn't reject | ✅ Fixed — mismatched tokens are now rejected outright |
| `alg: none` / HS256 downgrade on session JWTs | ✅ Fixed — algorithm pinned to `RS256` |
| No way to end a session | ✅ Fixed — `POST /api/auth/logout` revokes the `jti`; replay is rejected |
| No way to delete an account | ✅ Fixed — `DELETE /api/account` revokes the Google token and cascades |
| Unknown request fields accepted (mass assignment) | ✅ Fixed — strict schemas reject extras; token fields are allowlisted |
| CORS regex matched any installed Chrome extension | ✅ Fixed — exact-match allowlist pinned to the published extension ID |
| Restore could spend quota past budget / on retries | ✅ Fixed — reservation inside the request loop + daily circuit breaker |
| Repeated restores re-created playlists and duplicate tracks | ✅ Fixed — playlist cache, item mirror, TTL re-verification |
| Error responses could leak internal details | ✅ Fixed — generic 500s, redacted tokens, structured audit log |

**Before deploying, always set `APP_ENV=production`** — this is the flag that turns on all of the above protections.

[HARDENING.md](HARDENING.md) has the full item-by-item breakdown, including what is deliberately **not** enabled yet and what is blocked on an extension release.

---

## 🗺️ Roadmap

Done:

- [x] OAuth token refresh handling (single-flight) with dead-credential cleanup
- [x] Rate limiting on auth and restore endpoints
- [x] Encryption key management: versioned master keys with zero-downtime rotation
- [x] Session revocation and full account deletion

Open:

- [ ] PKCE / `state` / nonce validation — needs an extension release (see [HARDENING.md](HARDENING.md))
- [ ] Reliable server-side refresh — needs the extension to send `refresh_token`, `scope` and `expiry`
- [ ] External secrets manager (AWS KMS / GCP Secret Manager) instead of environment variables
- [ ] Pagination for `/api/snapshots`

---

## 📄 License

MIT — see `LICENSE`.
