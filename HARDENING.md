# Security & Quota Hardening

What changed, why, and what is still blocked on the extension.

Every item below carries one of three classifications:

| Tag | Meaning |
| :--- | :--- |
| **[SAFE]** | Shipped, on by default, no client change needed. Covered by tests. |
| **[COMPAT]** | Shipped but OFF by default, or on but log-only. Enabling it needs a decision. |
| **[NEEDS FRONTEND]** | Not possible from the backend alone. Requires an extension release. |

---

## 1. Google OAuth and token security

| Item | Status | Classification |
| :--- | :--- | :--- |
| PKCE, `state`, incremental authorization | Not implemented. The extension runs its OAuth flow through `chrome.identity.getAuthToken()` and posts the finished token to `/api/auth/register`. A backend code exchange needs a redirect URI and a client secret that this client does not have. | **[NEEDS FRONTEND]** |
| OpenID Connect validation | `auth.verify_google_id_token` validates signature, `aud`, `iss` and expiry via `google-auth`. `POST /api/auth/register` also verifies the access token against `oauth2.googleapis.com/tokeninfo` and rejects it when the `aud`/`azp` client does not match `YTM_CLIENT_ID`. | **[SAFE]** |
| AES-256-GCM envelope encryption | `crypto.py` encrypts each token set with a random 32-byte DEK under a master key, using the owner's `user_id` as AAD so a token cannot be moved between rows. Key IDs let you rotate without rewriting existing rows. | **[SAFE]** |
| Legacy token migration | Fernet (the old store) and the intermediate v2 envelope are still readable. A row is re-wrapped to v3 on first successful read, so old deployments upgrade lazily with no downtime. | **[SAFE]** |
| `invalid_grant` / dead credential handling | A 401 from YouTube raises `GoogleAuthError`. The restore route then deletes the dead token, sets `needs_reconnect`, and returns the **existing** 400 sign-in body the extension already handles. | **[SAFE]** |
| Token revocation | `auth.revoke_google_token` calls `oauth2.googleapis.com/revoke`. Wired into `DELETE /api/account`. | **[SAFE]** |
| Refresh-token persistence | A single-flight refresh avoids a refresh stampede. Whether the refreshed token is written back is `AUTH_PERSIST_REFRESHED_TOKEN`. | **[COMPAT]** (default off) |

### Why refresh cannot be made reliable here

`handlers.ts` sends exactly `token_data: {"access_token": <string>}`. `chrome.identity.getAuthToken()` yields no refresh token, no scope and no expiry. So:

- the backend cannot mint a refresh token it was never given;
- the stored token cannot be refreshed proactively, because its expiry is unknown;
- a 401 is only detectable mid-request, after the request has already been made.

The service therefore treats the access token as short-lived and fails cleanly into the sign-in path rather than looping.

---

## 2. Sessions, transport, gateway

| Item | Status | Classification |
| :--- | :--- | :--- |
| RS256 session JWTs | `auth.py` signs RS256 with `JWT_PRIVATE_KEY` and verifies with the pinned public key, exact issuer and audience. `algorithms=["RS256"]` is pinned, which is what rejects `alg: none` and any HMAC downgrade. | **[SAFE]** |
| HS256 compatibility | Removed. Existing sessions are invalidated once on deploy; the extension re-authenticates silently on its next request and no user-visible flow changes. | **[SAFE]** |
| Logout | `POST /api/auth/logout` records the `jti` in a `revoked_tokens` table. Replay returns 401 `Session token has been revoked`. | **[SAFE]** |
| Security headers | Middleware sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin` and `Permissions-Policy` on every response. `Cache-Control: no-store` covers every private path (auth, account, snapshots, restore); only `/`, `/health` and `/api/health` stay cacheable. | **[SAFE]** |
| HSTS / CSP | Enabled in production. `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. | **[SAFE]** |
| Strict origin matching | Exact-match allowlist; no wildcard suffix matching. Unknown origin is logged with a correlation ID. | **[SAFE]** (logged) / **[COMPAT]** (blocking) |
| CSRF | Bearer-token auth is inherently CSRF-immune and the service sets no cookies. | **[SAFE]** (no token needed) |
| Body / content-type limits | 2 MB request cap, 1000 tracks per snapshot, 16 KB token payload, and non-JSON bodies rejected with 415. | **[SAFE]** |
| Host header validation | Allowlist via `ALLOWED_HOSTS`; empty (the default) keeps platform-assigned hostnames working. | **[COMPAT]** |
| Rate limiting | Per-IP plus per-user restore limits, with the restore rate shared across the two restore routes. Caps sit far above real extension usage. | **[SAFE]** |
| Unhandled errors | The global handler returns a generic 500 and logs the real traceback, so connection strings and stack frames never reach a client. | **[SAFE]** |

---

## 3. Access control and data protection

| Item | Status | Classification |
| :--- | :--- | :--- |
| BOLA / tenant isolation | Ownership is re-checked on restore and delete; a foreign snapshot returns 403. Covered by tests. | **[SAFE]** |
| Schema validation | Pydantic models are bounded (`min_length`, `max_length`, video-ID pattern, max tracks) and strict (`extra="forbid"`), so unknown fields are rejected rather than ignored. | **[SAFE]** |
| Token field allowlist | Only the fields in `config.ALLOWED_TOKEN_FIELDS` are persisted from `token_data`; anything else is dropped before it reaches the database. | **[SAFE]** |
| Account deletion | `DELETE /api/account` revokes the Google token, deletes the user, and cascades to snapshots, cached playlists, the item mirror and the quota ledger. Returns 204. | **[SAFE]** |
| Token redaction | Access tokens, refresh tokens and Authorization headers are masked in every log line and audit event. Control characters are escaped so a crafted value cannot forge a log line. | **[SAFE]** |

---

## 4. Quota and cost control

| Item | Status | Classification |
| :--- | :--- | :--- |
| Ledger | `quota.QuotaTracker` records units per user per **Pacific** day, matching Google's reset boundary. | **[SAFE]** |
| Reserve before spend | Units are reserved inside the request loop, so a retry cannot slip past the ledger. | **[SAFE]** |
| Circuit breaker | `ensure_budget` refuses before any network call. Global cap defaults to 9500 of 10000, leaving headroom so an overshoot cannot cross Google's limit. | **[SAFE]** |
| Partial restore under budget | A snapshot larger than the user's remaining budget is restored **as far as the budget allows** instead of being refused whole. The caller still receives a real playlist; the tracks that did not fit are reported as failed and logged. See "Cap vs. capability" below. | **[SAFE]** |
| Playlist caching | `UserPlaylist` maps `(user_id, category)` to a playlist ID, so repeat restores reuse the playlist instead of creating another. Creation costs 50 units; reuse costs 0. | **[SAFE]** |
| Deleted-playlist recovery | A cached ID is re-verified with `playlists.list` (1 unit) once per `YTM_PLAYLIST_VERIFY_TTL_SECONDS`. If it is gone, a replacement is created and the stale cache row dropped. | **[SAFE]** |
| Item mirror | `PlaylistItemsCache` records what is already in a playlist, so a repeated track is not re-inserted at 50 units. | **[SAFE]** |
| Create-rate limit | `YTM_MAX_PLAYLIST_CREATES_PER_USER_PER_DAY` (default 20) stops a delete/recreate loop from draining the shared project quota. | **[SAFE]** |
| No 429 retries | `403 quotaExceeded` and `429` are never retried. Only 5xx and the transient `409 ABORTED` are. | **[SAFE]** |
| Retry cap | Bounded attempts with exponential backoff and jitter, capped by `YTM_RETRY_MAX_SECONDS`. | **[SAFE]** |
| Bounded response fields | `fields=` parameters on list calls; 304s are not relied on, since a 304 still costs units. | **[SAFE]** |
| ytmusicapi fallback | Creates a fresh playlist every run and bypasses the ledger, so it is **disabled in production**. Quota and auth failures never fall through to it. | **[COMPAT]** (on outside prod) |
| Dedupe within a snapshot | Collapses a video ID repeated inside one snapshot. | **[COMPAT]** (default off) |
| `videos.list` pre-validation | 1 unit per 50 IDs to avoid spending 50-unit inserts on dead IDs. | **[COMPAT]** (default off) |
| Durable replay queue | Would replay budget-refused restores after the Pacific reset. Off: the extension is synchronous, so a replay would create a playlist the user was told had failed. | **[COMPAT]** (default off) |

### Why the circuit breaker returns 502

`QUOTA_EXCEEDED_HTTP_STATUS=502` with `{"detail": "Failed to restore playlist to YouTube Music: ..."}` is the shape the extension already handles as a generic failure. Returning a new status code would need a client change, so the budget refusal is deliberately made indistinguishable from any other upstream failure. The internal reason is still recorded in the audit log.

### Cap vs. capability: why a restore can be partial

The per-user cap is **5,000 units**, but a single track costs **50** and creating a playlist costs **50**. That makes the largest single restore **99 tracks** — so a snapshot beyond that cannot be completed in one go, and it would previously have been refused outright with a `502`.

This is a genuine tension, and it is deliberate: the requirement is to stop one user from draining the shared 10,000-unit project quota, which a hard refusal satisfies but at the cost of the feature. The resolution chosen is a **partial restore**:

- the playlist is created and tracks are inserted until the budget runs out;
- the remaining IDs are returned in the `failed` list and logged with a count;
- the response is still `200` with a valid `playlist_url`;
- the cap is still never crossed — the per-track check happens *before* each insert.

A second restore picks up where the first stopped once the Pacific day rolls over, because the tracks that did fit are mirrored and skipped.

Note the honest limitation: the caller receives `200 success` with a **partial** playlist and has no field telling it which tracks were dropped, because the response shape is a frozen contract. A user whose snapshot exceeded their daily budget gets a shorter playlist and no visible signal. The dropped IDs are in the server logs. Changing this properly needs a response-shape change and therefore an extension release.

For reference, the schema accepts up to `MAX_TRACKS_PER_SNAPSHOT=1000`, but a 1000-track restore would cost 50,050 units — five times the entire daily project allowance. That ceiling is a validation limit, not a promise; raise `YTM_QUOTA_USER_CAP` if you need larger single restores and have the quota headroom for it.

---

## 5. Migrations

Additive, idempotent, and reversible. `create_all` runs first, then migrations that only ever `ADD COLUMN` / `CREATE TABLE` / `CREATE INDEX`, so an older database gains the new columns without losing rows. Applied automatically on startup; verified to be re-runnable.

| ID | Change | Rollback |
| :--- | :--- | :--- |
| `0001_quota_and_playlist_cache` | `quota_usage`, `user_playlists`, `playlist_items_cache` + indexes | drop the three tables |
| `0002_playlist_verification_ttl` | `user_playlists.verified_at` | drop column |
| `0003_user_reconnect_flag` | `users.needs_reconnect`, `users.last_seen_at` | drop columns |
| `0004_quota_playlists_created` | `quota_usage.playlists_created` | drop column |
| `0005_performance_indexes` | composite indexes for the hot lookups | drop indexes |

To roll back manually, run the `downgrade` statement in `migrations.py` for the highest ID you want removed. Rolling back drops cached state, never user snapshots or accounts.

---

## 6. Verification

```bash
cd backend
python -m pytest tests -q
```

79 tests, no network access, no YouTube quota. They cover the frozen extension contract (exact response bodies and status codes), tenant isolation, input validation, quota accounting, warm-restore cost, partial restores, retry policy, encryption round-trips and error redaction. The suite is order-independent and each file also passes in isolation.

Three real bugs were found this way and fixed:

- the HTTP verb was derived from the API method name, so every call was issued as `PLAYLISTS.INSERT` instead of `POST`;
- a `return` nested inside an `except` block meant a *successful* commit fell through to creating a duplicate playlist, so every restore spent 50 units it did not need to;
- the playlist TTL compared a naive timestamp against an aware one via a `replace(tzinfo=...)` call that was passing a *datetime* where a *tzinfo* was expected, which would have raised on the first cached re-restore.

A fourth gap was closed from a failing assertion rather than a crash: `Cache-Control: no-store` was only applied to `/api/auth*`, so `GET /api/snapshots` was returning user data with no cache directive at all.

---

## 7. Outstanding work

| Item | Why it is blocked |
| :--- | :--- |
| PKCE / `state` / nonce validation | Needs an extension release that performs the code exchange. |
| Server-side refresh | Needs the extension to send `refresh_token`, `scope` and `expiry`. |
| Blocking Origin enforcement | Safe to enable once `ALLOWED_ORIGINS` is confirmed; kept log-only so a misconfiguration cannot lock out real users. |
| Live quota verification | Requires real Google credentials and a real project; the suite uses an in-memory HTTP fake. |