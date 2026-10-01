# Security Hardening

Summary of the security review performed on the service and the changes it produced. The item-by-item table is in [HARDENING.md](../HARDENING.md); this document explains the reasoning.

## Method

Each control was classified before implementation:

| Tag | Meaning |
|---|---|
| **SAFE** | Needs no client change. Shipped and on by default. |
| **COMPAT** | Shipped but off by default, or log-only, until a deployment decision is made. |
| **NEEDS FRONTEND** | Cannot be done by the backend alone. Requires an extension release. |

This split matters because the published extension fixes the API contract. Anything that would change a response or require a new client behavior had to be flagged, not forced.

## 1. Credentials and tokens

### Envelope encryption (SAFE)

Stored OAuth tokens previously used Fernet (AES-128-CBC, no authenticated context), with a key derived from the JWT signing secret. That meant one leaked secret compromised both sessions and stored tokens, and an encrypted blob could be copied from one user's row to another's.

The replacement, in `crypto.py`:

- **AES-256-GCM** with a random 12-byte nonce.
- A random 32-byte data key per record, wrapped by a master key from `KMS_MASTER_KEY`.
- The owner's **`user_id` as additional authenticated data**, so a blob moved to another row fails to decrypt.
- **Key IDs** so the master key can rotate without rewriting rows. Records are re-wrapped lazily on next read.
- **Lazy migration** of Fernet and earlier envelope formats, so existing users are upgraded without downtime.

The encryption key is independent of the signing key. In production both are required.

### Dead credentials (SAFE)

If Google returns `401` or `invalid_grant` during a restore, the service deletes the dead token, sets `needs_reconnect`, and returns the existing `400` sign-in response the extension already handles. It does not retry in a loop.

### Revocation (SAFE)

`DELETE /api/account` calls `oauth2.googleapis.com/revoke` before deleting the user, so the grant is removed on Google's side too.

### Not possible from the backend (NEEDS FRONTEND)

- **PKCE, `state`, incremental authorization.** The extension performs OAuth through `chrome.identity.getAuthToken()` and posts the finished token. A backend code exchange needs a redirect URI and client secret this client does not use.
- **Reliable refresh.** The extension sends only `{"access_token": ...}`. Without a refresh token, scope or expiry, the backend cannot refresh proactively and treats the token as short-lived.

## 2. Sessions and transport

| Control | Detail |
|---|---|
| RS256 JWTs | Asymmetric signing; `algorithms=["RS256"]` is pinned, which rejects `alg: none` and HMAC downgrade. Exact issuer and audience are enforced. |
| Revocation | `POST /api/auth/logout` stores the `jti`; replay returns `401`. |
| Security headers | `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` on all responses; `Cache-Control: no-store` on every private path. HSTS and CSP in production. |
| CORS | Exact-match origin allowlist. No wildcard or regex matching of `chrome-extension://` origins. |
| CSRF | Not applicable: authentication uses a Bearer header and the service sets no cookies. |
| Request limits | 2 MB body cap, 1,000 tracks per snapshot, 16 KB token payload, `415` on non-JSON bodies. |
| Rate limiting | Per-IP and per-user limits on auth and restore routes. |
| Error handling | Generic `500` responses; real tracebacks are logged server-side only. Tokens and Authorization headers are redacted from logs, and control characters are escaped to prevent log forging. |

## 3. Access control and data protection

- **Object-level authorization.** Snapshot IDs are sequential integers, so guessing them is trivial. Every delete and restore verifies `snapshot.user_id == current_user.id` and returns `403` otherwise. There is no anonymous identity anywhere in the request path.
- **Input validation.** Strict Pydantic schemas with `extra="forbid"`. Video IDs must match `[A-Za-z0-9_-]{1,32}`. Only an allowlist of fields from the client's token payload is persisted.
- **Data minimization.** Account deletion cascades to snapshots, cached playlists, the item mirror and quota records.

## 4. Findings from the self-review

| Finding | Risk | Resolution |
|---|---|---|
| Missing `Authorization` header fell back to a default user | Every protected route reachable anonymously | Fallback removed; always `401` |
| Dev-only login route reachable in production | One-request account takeover | Returns `404` when `APP_ENV=production` |
| Hardcoded fallback JWT secret | Forgeable sessions | Production refuses to boot without keys |
| Encryption key derived from JWT secret | Single leak compromises both | Independent keys |
| Fernet without AAD | Tokens swappable between users | AES-256-GCM with `user_id` as AAD |
| Google token audience mismatch only logged | Tokens for other apps accepted | Mismatches rejected |
| CORS regex matched any Chrome extension | Any installed extension could call the API | Exact-match allowlist |
| Unvalidated `videoId` (500 chars) | Oversized and malformed input | Strict pattern and length |
| `Cache-Control` set only on `/api/auth*` | Snapshot data cacheable | `no-store` on all private paths |
| Container ran as root | Larger blast radius on compromise | Dedicated non-root user |

## 5. Design principle

Missing configuration should **fail loudly**, not be replaced with a working but insecure default. In development, missing keys are generated per run with a warning. In production the application will not start.

## 6. Verification

Tests cover the frozen contract, tenant isolation, input validation, encryption round-trips (including cross-user substitution), token redaction, and security headers. One header gap was found by a failing assertion rather than by review, which is the argument for testing these properties instead of trusting them.

## 7. Remaining work

| Item | Blocker |
|---|---|
| PKCE, `state`, nonce validation | Extension release |
| Server-side token refresh | Extension must send `refresh_token`, `scope`, `expiry` |
| Blocking origin enforcement | Kept log-only until `ALLOWED_ORIGINS` is confirmed, so a misconfiguration cannot lock out users |
| External secrets manager | Infrastructure decision |
