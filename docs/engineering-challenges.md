# Engineering Challenges

Twelve problems encountered while building the backend, in roughly the order they appeared. Each lists the cause, the resolution, and what it changed in how the code is written.

Related: [Quota optimization](quota-optimization.md) · [Security hardening](security-hardening.md)

---

## Reliability and operations

### 1. Startup crash with an unhelpful traceback

**Symptom.** The app failed at import time with a `TypeError` whose traceback pointed into SQLAlchemy internals.

**Cause.** A column was declared with `primary_class=True` instead of `primary_key=True`. SQLAlchemy rejects unknown keyword arguments when the model class is built, which happens before the server finishes booting.

**Resolution.** Reviewed every column definition against the documentation and fixed the typo.

**Takeaway.** Errors raised at import time hide their origin. Linting and typing plugins catch this class of mistake earlier.

### 2. Managed Postgres rejected by the ORM

**Symptom.** Connections failed in production but worked locally.

**Cause.** Managed hosts supply `postgres://` URLs; SQLAlchemy 2.x requires `postgresql://`.

**Resolution.** Added URL normalization at startup, and kept a SQLite fallback for zero-configuration local development.

### 3. CORS blocked the extension

**Symptom.** Requests from the Chrome extension were rejected.

**Cause.** Extension origins look like `chrome-extension://<id>`, which standard CORS configuration does not anticipate. The first workaround, a regex allowing any `chrome-extension://` origin, would have let any installed extension call the API.

**Resolution.** Replaced the regex with an exact-match allowlist pinned to the published extension ID. Unknown origins are logged with a correlation ID.

### 4. Container ran as root

**Cause.** Base Python images default to root.

**Resolution.** Added a dedicated `appuser`, changed ownership of the app directory, and switched the container to that user.

---

## Cost and correctness

### 5. Large restores timed out, and the fix made things worse

**Symptom.** Restoring 100+ tracks took 15 to 25 seconds, exceeding the extension's fetch timeout.

**First fix.** The YouTube API has no batch-add endpoint, so inserts were parallelized with a bounded thread pool.

**Why it was reversed.** Concurrent writes to one playlist returned `409 ABORTED / SERVICE_UNAVAILABLE`, and each retry could cost another 50 quota units.

**Resolution.** Inserts are sequential again. The real improvement was making fewer calls: playlists are cached and tracks already present are skipped, so a repeat restore costs 0 units.

**Takeaway.** The slow path was a symptom. Increasing the request rate while the request count stayed the same only consumed the daily quota faster.

### 6. Quota accounting existed but did not hold

**Symptom.** A usage tracker was wired in, yet usage was undercounted.

**Cause.** The tracker only saw calls routed through one helper. Calls that bypassed it were never recorded, and a retry could pass a budget that had been checked once at the start.

**Resolution.** Units are reserved inside the request loop, so every attempt is charged before it is sent. The budget is checked before any network call. Three regression tests pin this behavior.

### 7. A misplaced `return` doubled the quota bill

**Symptom.** None visible. Every restore returned `200`.

**Cause.** In `resolve_playlist`, a `return` sat inside an `except` block. A *successful* database commit therefore fell through and created a second playlist, spending 50 units unnecessarily on every restore. Only the quota ledger revealed it.

**Resolution.** Corrected the control flow and added `test_warm_restore_spends_zero_units`, which asserts a repeat restore makes **no** YouTube call and adds zero units.

**Takeaway.** To pin a cost guarantee, test that something does *not* happen. A passing response does not prove correct behavior.

### 8. Per-user cap versus a working feature

**Problem.** A 5,000-unit per-user cap allows at most 99 tracks per restore. Refusing larger snapshots would protect the quota but break the feature.

**Resolution.** Partial restore: insert until the budget is reached, return a real playlist, log what was dropped, and resume on the next quota day. The limitation (the caller cannot see dropped tracks) is documented because the response format is frozen. Details in [quota optimization](quota-optimization.md#4-cap-versus-capability).

---

## Security

### 9. Authentication could be bypassed

**Cause.** `get_current_user` returned a default user when no `Authorization` header was sent, so every protected route was reachable anonymously.

**Resolution.** Removed the fallback. Missing or invalid credentials always return `401`.

### 10. Development login shortcut reachable in production

**Cause.** `/api/auth/test-login` issued real session tokens with no verification and nothing prevented it from being exposed in a deployment.

**Resolution.** The route returns `404` (not `403`, so it does not confirm it exists) when `APP_ENV=production`.

### 11. Guessable object IDs

**Cause.** Snapshot IDs are sequential integers. Without an ownership check, `DELETE /api/snapshots/5` could affect another user's data.

**Resolution.** Every delete and restore verifies ownership and returns `403` before any other work. Covered by tests.

### 12. Secrets handled as conveniences

**Cause.** The JWT secret had a hardcoded fallback, and the token-encryption key was derived from it, so one leak exposed both sessions and stored credentials.

**Resolution.** Independent keys, RS256 for sessions, and a production mode that refuses to start without explicit secrets. In development, keys are generated per run with a visible warning.

**Takeaway.** "Do not crash on missing configuration" and "do not substitute a fake value" are different goals. The first should mean failing with a clear message, not silently continuing with something insecure.

---

## Constraint that shaped all of this

The API contract with the published extension is frozen. Every fix above had to preserve response bodies and status codes. `tests/test_contract.py` replays the extension's actual requests and asserts the exact responses, so a client-breaking change fails the test suite instead of production.
