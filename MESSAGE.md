# YouTube API Quota Optimization & Security Hardening

Engineering summary of the changes made to reduce YouTube Data API v3 quota spend, prevent concurrency bugs, and harden the service — without changing anything the published extension depends on.

The API contract (routes, methods, status codes, response bodies) is **frozen**. `tests/test_contract.py` replays the exact requests `extension/src/background/handlers.ts` makes and asserts the exact responses, so a client-breaking change fails the suite rather than production.

---

## 1. YouTube API Quota

### The problem

Every `POST /api/restore/{snapshot_id}` used to build a brand-new playlist and insert every track again:

| Operation | Units |
| :--- | ---: |
| `playlists.insert` | 50 |
| `playlistItems.insert` (per track) | 50 |

A 100-track snapshot therefore cost **5,050 units**, and a 200-track snapshot **10,050** — over the 10,000-unit default daily allowance in a single request. Re-restoring a saved snapshot paid the full cost again, and parallel inserts (a bounded `ThreadPoolExecutor`) turned into `409 ABORTED / SERVICE_UNAVAILABLE` conflicts where each retry cost another 50 units.

### What changed

**A. Local state mirror (additive schema)**

| Model | Purpose |
| :--- | :--- |
| `UserPlaylist` | maps `(user_id, snapshot_category)` → `youtube_playlist_id` |
| `PlaylistItemsCache` | which `video_id`s are already in a given playlist |
| `QuotaUsage` | units spent per user per **Pacific** day |

**B. Find-or-create instead of always-create**

A cached playlist ID is reused for **0 units** while it is inside `YTM_PLAYLIST_VERIFY_TTL_SECONDS` (900s). Once the TTL expires it is re-verified with `playlists.list` for **1 unit**; if the user deleted it, a replacement is created and the stale cache row dropped.

**C. Item mirror**

Track inserts are skipped when the ID is already mirrored for that playlist. An empty mirror on a reused playlist is rebuilt once via `playlistItems.list` (**1 unit per 50 items**), which is what makes the skip trustworthy.

**D. Quota circuit breaker**

Units are reserved **inside** the request loop, so every attempt — including retries — is charged before dispatch. `ensure_budget` refuses before any network call once global usage reaches **9,500** or a single user passes **5,000**, keeping headroom so an overshoot cannot cross Google's limit.

Because the cap is enforced *per track* rather than *up front*, a snapshot too large for the remaining budget is restored **partially**: the playlist is created, tracks are inserted until the budget runs out, and the leftover IDs are reported as failed. This keeps the feature usable at the cap instead of refusing the whole restore, and still never crosses the limit.

**E. Retry policy**

`403 quotaExceeded` and `429` are **never** retried: a failed retry still spends quota. Only `5xx` and the transient `409 ABORTED` are, with bounded attempts and capped exponential backoff with jitter.

**F. Per-user playlist creation cap**

`YTM_MAX_PLAYLIST_CREATES_PER_USER_PER_DAY` (20) stops a delete/recreate loop from draining the shared project quota.

### Resulting cost

| Scenario | Before | After |
| :--- | ---: | ---: |
| First restore, 100 tracks | 5,050 | **5,000** (99 tracks fit; 1 dropped) |
| Repeat restore within TTL | 5,050 | **0** |
| Repeat restore after TTL | 5,050 | **51** (1 re-verify + 50 for the 1 remaining track) |
| Re-restore with 0 new tracks | 5,050 | **0** |
| Restore of a playlist deleted in YouTube | 5,050 | 51 |

The per-user cap of **5,000** is what bounds the first row: at 50 units per track plus 50 for the playlist, 99 tracks is the largest single restore. Raise `YTM_QUOTA_USER_CAP` if you need larger restores and have the project headroom for it.

When the budget is exhausted the service returns **`502`** with the `{"detail": "Failed to restore playlist to YouTube Music: ..."}` body the extension already handles as a generic failure. The internal reason is recorded in the audit log; inventing a new status code would require a client change.

One limitation worth stating plainly: a partial restore returns **`200 success`** with a real playlist and no field saying which tracks were dropped, because the response shape is a frozen contract. The dropped IDs are in the server logs. Surfacing them needs an extension release.

---

## 2. Security hardening

| Area | Change |
| :--- | :--- |
| Token encryption | AES-256-GCM **envelope**: a random DEK per record under `KMS_MASTER_KEY`, with `user_id` as AAD so a token cannot be moved between rows. Fernet and the v2 envelope stay readable and are re-wrapped on first read, so the migration is lazy and needs no downtime. |
| Sessions | `HS256` → **RS256**, with `algorithms=["RS256"]` pinned (this is what rejects `alg: none` and HMAC downgrade), plus exact issuer/audience checks. |
| Logout | `POST /api/auth/logout` records the `jti`; replay returns `401 Session token has been revoked`. |
| Dead credentials | A `401` from YouTube raises `GoogleAuthError`; the route deletes the token, sets `needs_reconnect`, and returns the **existing** 400 sign-in body. |
| Account deletion | `DELETE /api/account` revokes the Google token and cascades across snapshots, playlist cache, item mirror and quota ledger. |
| Headers | Middleware applies `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and HSTS/CSP in production. `Cache-Control: no-store` covers every private path — only `/`, `/health` and `/api/health` stay cacheable. |
| Input | Strict schemas (`extra="forbid"`), bounded strings, a `[A-Za-z0-9_-]{1,32}` video-ID pattern, 1000 tracks max, 2 MB body cap, non-JSON bodies rejected with `415`. Only allowlisted token fields are persisted. |
| Access control | Ownership re-checked on restore and delete; a foreign snapshot is `403`. Missing or invalid credentials are always `401`. |
| Transport | Exact-match CORS allowlist (no wildcard), optional Host allowlist, rate limits per-IP and per-user. |
| Error handling | Global handler returns a generic `500` and logs the traceback; tokens and Authorization headers are redacted and control characters escaped so a value cannot forge a log line. |

`APP_ENV=production` makes every one of these fail closed: required secrets, no test-login route, no Swagger, no `ytmusicapi` fallback (which creates a playlist per run and bypasses the ledger entirely).

---

## 3. What the test suite found

`python -m pytest tests -q` → 79 tests, no network, no quota consumed. It exists to catch the class of bug that returns a perfectly valid `200` while doing the wrong thing:

- **Every YouTube call used the wrong HTTP verb.** The verb was derived from the API method name, so requests went out as `PLAYLISTS.INSERT` rather than `POST`. Every restore failed.
- **Every restore created a duplicate playlist.** A `return` nested inside an `except` block meant a *successful* commit fell through to `_create_playlist`, spending 50 units per restore for nothing. Responses were still `200`.
- **The cache TTL would have thrown on first use.** A naive timestamp was being made aware via `replace(tzinfo=...)` passing a *datetime* where a *tzinfo* was expected.
- **User data was cacheable.** `Cache-Control: no-store` was scoped to `/api/auth*`, so `GET /api/snapshots` returned saved queues with no cache directive.

Each is now pinned by a regression test — including `test_warm_restore_spends_zero_units`, which asserts the second restore makes **no** YouTube call and adds **zero** units. Asserting a negative is the only way to hold a cost guarantee in place.

---

## 4. Outstanding

| Item | Why |
| :--- | :--- |
| PKCE / `state` / nonce | Needs an extension release; `chrome.identity.getAuthToken()` gives the backend a finished token, not a code to exchange. |
| Reliable server-side refresh | Needs the extension to send `refresh_token`, `scope` and `expiry`. Today only `access_token` arrives. |
| Live quota verification | Requires real Google credentials; the suite uses an in-memory HTTP fake. |

See [HARDENING.md](HARDENING.md) for the full classification and [README.md](README.md) for deployment and rollback.