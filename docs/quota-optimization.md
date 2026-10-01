# YouTube API Quota Optimization

How the restore path was changed to fit inside a shared 10,000-unit daily quota, without changing anything the published extension depends on.

## 1. Audit

All YouTube Data API calls originate from `POST /api/restore/{snapshot_id}`.

| Operation | Endpoint | Cost (units) | Frequency |
|---|---|---:|---|
| Create playlist | `playlists.insert` | 50 | Once per restore |
| Add track | `playlistItems.insert` | 50 | Once per track |

| Snapshot size | Cost per restore |
|---:|---:|
| 100 tracks | 5,050 units |
| 200 tracks | 10,050 units (the entire daily project quota) |

The quota is shared by every user of the application, so one large restore could lock everyone out until the daily reset.

### Sources of waste

1. **No playlist reuse.** Every restore created a new playlist and re-inserted every track, even for an unchanged queue.
2. **Concurrent writes.** Tracks were inserted by a thread pool. Concurrent writes to one playlist triggered `409 ABORTED / SERVICE_UNAVAILABLE` responses, and each retry could cost another 50 units.
3. **No deduplication.** Nothing checked whether a video was already in the target playlist.

## 2. Constraint: a frozen API contract

The extension is already published, so the endpoint's behavior is fixed.

`POST /api/restore/{snapshot_id}` with `Authorization: Bearer <token>`:

```json
{ "status": "success", "ytm_playlist_id": "...", "playlist_url": "..." }
```

Errors: `401` invalid or missing token, `403` not the snapshot owner, `404` snapshot not found, `502` restore failed.

Every change below happens behind this interface. `tests/test_contract.py` enforces it.

## 3. Changes

### 3.1 Local state (additive schema)

| Table | Purpose |
|---|---|
| `user_playlists` | Maps `(user_id, category)` to a YouTube playlist ID |
| `playlist_items_cache` | Video IDs known to be in each playlist |
| `quota_usage` | Units spent per user and globally, per Pacific day |

### 3.2 Find or create

A cached playlist is reused at **0 units** while it is inside a verification window (`YTM_PLAYLIST_VERIFY_TTL_SECONDS`, default 900). After the window it is re-verified with `playlists.list` at **1 unit**. If the user deleted the playlist, a new one is created and the stale cache entry removed.

### 3.3 Item mirror and deduplication

Before inserting, tracks already present in the mirror are skipped. If a reused playlist has an empty mirror, it is rebuilt once with `playlistItems.list` at 1 unit per 50 items. Each successful insert is recorded in the mirror immediately, so a retry cannot double-write.

### 3.4 Sequential inserts

Parallel inserts were removed. With deduplication in place most restores insert few or no tracks, so the speed advantage of concurrency no longer matters, and the `409` conflicts and their retry cost are gone.

### 3.5 Budget and circuit breaker

`quota.QuotaTracker` records units per user per **Pacific-time** day, which matches when Google resets the quota.

- Units are **reserved inside the request loop**, before each attempt, so retries are charged.
- `ensure_budget` runs before any network call.
- Default caps: **9,500** units globally (95% of 10,000, leaving headroom) and **5,000** per user.
- A per-user limit on playlist creations per day (default 20) stops a delete-and-recreate loop from draining the shared quota.
- `403 quotaExceeded` and `429` responses are never retried.

### 3.6 Why the breaker returns 502

The extension already handles `502` with `{"detail": "Failed to restore playlist to YouTube Music: ..."}` as a generic failure. A new status code would need a client release, so a budget refusal is made indistinguishable from any other upstream failure. The real reason is recorded in the audit log.

## 4. Cap versus capability

The per-user cap is 5,000 units, and creating a playlist or inserting a track each costs 50. The largest restore a single user can complete in one day is therefore **99 tracks**. Refusing larger snapshots protects the shared quota but disables the feature for exactly the users who want it most.

The resolution is a **partial restore**:

- the playlist is created and tracks are inserted until the budget runs out;
- the check happens before each insert, so the cap is never crossed;
- the response is still `200` with a valid `playlist_url`;
- dropped video IDs are logged with a count;
- a second restore after the Pacific-day reset continues where the first stopped, because inserted tracks are mirrored and skipped.

**Limitation:** the caller receives no signal that tracks were dropped, because the response shape is frozen. Surfacing this needs a contract change and therefore an extension release.

The schema accepts up to 1,000 tracks per snapshot, but a 1,000-track restore would cost over 50,000 units, five times the daily project quota. That value is a validation ceiling, not a supported restore size. `YTM_QUOTA_USER_CAP` can be raised where headroom exists.

## 5. Results

| Scenario | Before | After |
|---|---:|---:|
| First restore, 100 tracks | 5,050 units | 5,050 units (unavoidable writes) |
| Repeat restore, unchanged queue | 5,050 units | **0 units**, no YouTube call |
| Repeat restore, 5 new tracks | 5,050 units | 250 units |
| Retry after `409` | Extra 50 per retry, uncounted | Charged and bounded |

## 6. Verification

Tests assert behavior, including the absence of calls:

- a warm repeat restore makes **no** YouTube request and adds **zero** units;
- retries are charged against the budget;
- a snapshot over budget produces a partial playlist and never exceeds the cap;
- the response body and status codes match the frozen contract.

## 7. Migrations and rollback

Schema changes are additive and applied at startup. To roll back, revert the code and optionally drop the new tables:

```sql
DROP TABLE quota_usage, playlist_items_cache, user_playlists;
```

User snapshots and accounts are never touched.
