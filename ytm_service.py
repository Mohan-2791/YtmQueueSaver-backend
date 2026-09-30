"""
YouTube Music restore path.

Quota model (https://developers.google.com/youtube/v3/determine_quota_cost)
------------------------------------------------------------------------
    playlists.insert      50 units
    playlistItems.insert  50 units   <- the only unavoidable per-track cost
    playlists.list         1 unit    (existence check for a cached playlist ID)
    playlistItems.list     1 unit    (per 50 items; only used to rebuild the mirror)
    videos.list            1 unit    (per 50 IDs; optional pre-validation)
    search.list          100 units   <- never called: the snapshot already has IDs

A naive 100-track restore therefore costs 50 + 100*50 = 5,050 units. With the
caching, deduplication and TTL verification implemented here a *warm* re-restore
of the same snapshot costs **0 units**, and the first restore of a new queue
costs 50 (playlist) + 50*N (new tracks only).

Everything else in this module is defensive: retries are bounded and only ever
applied to genuinely transient failures, because a failed retry still consumes
quota. Quota is reserved *before* each call (see quota.py), never after.
"""

import datetime
import json
import logging
import os
import random
import tempfile
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

import requests
from requests.adapters import HTTPAdapter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ytmusicapi import OAuthCredentials, YTMusic

import config
import models
import quota
from auth import _token_expired, refresh_access_token

logger = logging.getLogger("ytm_saver.service")

YOUTUBE_API_BASE = "https://www.googleapis.com/youtube/v3"

# Recreate-and-replay when a cached playlist ID turns out to be gone.
MAX_PLAYLIST_RESOLUTION_ATTEMPTS = 2
# Flush the local mirror to the DB in batches rather than one commit per track.
CACHE_FLUSH_BATCH_SIZE = 25
# Guard against a provider that keeps handing back the same page token.
MAX_PAGES_PER_LIST_CALL = 100

_RETRYABLE_STATUS = frozenset({409, 500, 502, 503, 504})
_QUOTA_ERROR_REASONS = frozenset(
    {"quotaExceeded", "dailyLimitExceeded", "userRateLimitExceeded", "rateLimitExceeded"}
)
# YouTube API method name -> HTTP verb. `method` below is always the API method
# name (it is what the quota table is keyed on), so the verb has to be looked up
# explicitly rather than derived from it.
_HTTP_VERBS = {
    "playlists.list": "GET",
    "playlists.insert": "POST",
    "playlistItems.list": "GET",
    "playlistItems.insert": "POST",
    "videos.list": "GET",
}


def _utcnow() -> datetime.datetime:
    """Naive UTC, matching the columns' `DateTime` storage convention."""
    return datetime.datetime.utcnow()


def _utcnow_aware() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class GoogleAuthError(RuntimeError):
    """401 from the Data API: the stored credential is dead or expired."""


class YouTubePlaylistDeleted(RuntimeError):
    """404 playlistNotFound: the cached playlist ID no longer resolves."""


# --- Thread-local HTTP session ------------------------------------------------
# `requests.Session` keeps the TLS connection alive, so a restore that makes
# dozens of calls pays one handshake instead of dozens. Sessions are not
# documented as thread-safe, so each worker thread gets its own.
_local = threading.local()


def _http_session() -> requests.Session:
    session = getattr(_local, "session", None)
    if session is None:
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=16, max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update(
            {
                "User-Agent": "ytm-queue-saver/1.1",
                "Accept": "application/json",
            }
        )
        _local.session = session
    return session


class YTMService:
    def __init__(self, token_data: dict, db: Session = None, user_id: int = None):
        self.token_data = token_data or {}
        self.db = db
        self.user_id = user_id
        self.client_id = config.GOOGLE_CLIENT_ID
        self.client_secret = os.getenv("YTM_CLIENT_SECRET", "")

        # If your Google OAuth client is a "confidential" client type (as
        # opposed to a public/installed client), ytmusicapi's OAuth flow
        # needs the client secret to refresh tokens. An empty value here
        # won't necessarily break anything (public clients don't need one),
        # but if restores start failing with auth errors in production and
        # this is empty, check your OAuth client type first.
        if not self.client_secret and config.FLAG_ALLOW_YTMUSICAPI_FALLBACK:
            logger.warning(
                "YTM_CLIENT_SECRET is not set. This is fine for a public/installed OAuth "
                "client, but if your Google OAuth client is a confidential client type, "
                "token refresh during playlist restore will fail."
            )

        self._tracked_methods = 0

    # ------------------------------------------------------------------ #
    # Quota-aware HTTP primitives
    # ------------------------------------------------------------------ #
    @property
    def tracker(self) -> Optional[quota.QuotaTracker]:
        if self.db is None or not self.user_id:
            return None
        return quota.QuotaTracker(self.db)

    def _reserve(self, method: str) -> None:
        tracker = self.tracker
        if tracker is None:
            return
        tracker.reserve(self.user_id, config.ytm_unit_cost(method), method=method)

    @staticmethod
    def _affordable(user_id, tracker: "quota.QuotaTracker", units: int) -> bool:
        """Non-raising budget probe, for decisions that can degrade gracefully."""
        try:
            # The user id matters: ensure_budget skips the per-user cap when it
            # is None, so probing without it would approve work that _reserve
            # then rejects with UserQuotaExceeded mid-restore.
            tracker.ensure_budget(user_id, units)
        except quota.QuotaBudgetExceeded:
            return False
        return True

    @staticmethod
    def _classify(method: str, response: requests.Response):
        """
        Turn a response into (action, payload).

        action is one of "ok" | "retry" | "auth" | "quota" | "notfound" | "fail".
        """
        if response.ok:
            return "ok", response

        status_code = response.status_code
        reason = ""
        try:
            body = response.json()
            reason = (
                (body.get("error") or {}).get("errors", [{}])[0].get("reason", "")
                if isinstance(body.get("error"), dict)
                else ""
            )
        except ValueError:
            body = {}

        if status_code == 401:
            return "auth", response
        if status_code == 404:
            return "notfound", response
        if status_code in (403, 429) and (
            reason in _QUOTA_ERROR_REASONS or status_code == 429
        ):
            return "quota", response
        if status_code in _RETRYABLE_STATUS:
            return "retry", response
        return "fail", response

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: dict,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
        max_retries: Optional[int] = None,
    ) -> Tuple[str, Optional[requests.Response], dict]:
        """
        Issue one YouTube call, charging quota per attempt.

        Returns (action, response, parsed_json). `action` mirrors
        `_classify` plus "fail" for non-transient errors. Never raises for
        HTTP-level problems so callers can decide; network errors are treated
as retryable.
        """
        verb = _HTTP_VERBS[method]
        attempts_allowed = 1 + (
            config.YTM_MAX_RETRIES if max_retries is None else max_retries
        )
        parsed: dict = {}
        action = "fail"
        response = None

        for attempt in range(1, attempts_allowed + 1):
            self._reserve(method)
            self._tracked_methods += 1
            try:
                response = _http_session().request(
                    verb,
                    url,
                    headers=headers,
                    json=json_body,
                    params=params,
                    timeout=config.YTM_HTTP_TIMEOUT_SECONDS,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Network error calling %s (attempt %d/%d): %s",
                    method, attempt, attempts_allowed, exc,
                )
                response = None
                action = "retry"
            else:
                action, _ = self._classify(method, response)

            if action != "retry":
                break

            if attempt < attempts_allowed:
                delay = min(
                    config.YTM_RETRY_BASE_SECONDS * (2 ** (attempt - 1))
                    + random.uniform(0, config.YTM_RETRY_BASE_SECONDS),
                    config.YTM_RETRY_MAX_SECONDS,
                )
                logger.info(
                    "Transient failure on %s (attempt %d/%d); retrying in %.2fs%s",
                    method, attempt, attempts_allowed, delay,
                    f" status={response.status_code}" if response is not None else "",
                )
                time.sleep(delay)

        if response is not None and response.ok:
            try:
                parsed = response.json()
            except ValueError:
                parsed = {}
        return action, response, parsed

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _redact(response: Optional[requests.Response]) -> str:
        if response is None:
            return "no response"
        text = response.text or ""
        return f"{response.status_code} {text[:200]}"

    # ------------------------------------------------------------------ #
    # Playlist resolution (find-or-create)
    # ------------------------------------------------------------------ #
    def _cached_playlist_row(self, category: str) -> Optional[models.UserPlaylist]:
        if self.db is None or not self.user_id or not category:
            return None
        return (
            self.db.query(models.UserPlaylist)
            .filter_by(user_id=self.user_id, category=category)
            .first()
        )

    def _verify_playlist_still_exists(self, playlist_id: str, headers: dict) -> bool:
        action, response, body = self._request_with_retry(
            "playlists.list",
            f"{YOUTUBE_API_BASE}/playlists",
            headers=headers,
            params={"part": "id", "id": playlist_id, "fields": "items(id)"},
            max_retries=1,
        )
        if action == "ok":
            return bool(body.get("items"))
        if action == "notfound":
            return False
        # Quota/auth problems propagate; anything else is treated as "assume it
        # still exists" so a transient 5xx cannot cost the user their playlist.
        if action == "auth":
            raise GoogleAuthError(f"YouTube rejected the stored credential: {self._redact(response)}")
        if action == "quota":
            raise quota.YouTubeQuotaDepleted(
                "YouTube API quota exceeded upstream. Please try again later today."
            )
        logger.warning(
            "Could not verify playlist %s (%s); assuming it exists",
            playlist_id, self._redact(response),
        )
        return True

    def _create_playlist(
        self, title: str, playback_mode: str, headers: dict, category: str
    ) -> str:
        tracker = self.tracker
        if tracker is not None:
            tracker.ensure_budget(self.user_id, config.ytm_unit_cost("playlists.insert"))
            tracker.ensure_can_create_playlist(self.user_id)

        action, response, body = self._request_with_retry(
            "playlists.insert",
            f"{YOUTUBE_API_BASE}/playlists",
            headers=headers,
            json_body={
                "snippet": {
                    "title": (title or "Restored Queue")[:100],
                    "description": f"Restored via YTM Queue Saver ({playback_mode} Mode)"[:5000],
                },
                "status": {"privacyStatus": "private"},
            },
            params={"part": "snippet,status", "fields": "id"},
        )
        if action == "auth":
            raise GoogleAuthError(f"YouTube rejected the stored credential: {self._redact(response)}")
        if action == "quota":
            raise quota.YouTubeQuotaDepleted(
                "YouTube API quota exceeded upstream. Please try again later today."
            )
        if action != "ok":
            raise RuntimeError(
                f"YouTube Data API playlist creation failed: {self._redact(response)}"
            )

        playlist_id = body.get("id")
        if not playlist_id:
            raise RuntimeError("YouTube API response missing playlist ID")

        if self.db is not None and self.user_id and category:
            row = self._cached_playlist_row(category)
            if row is None:
                row = models.UserPlaylist(
                    user_id=self.user_id,
                    category=category,
                    youtube_playlist_id=playlist_id,
                    verified_at=_utcnow(),
                    title=(title or "")[:255],
                )
                self.db.add(row)
            else:
                row.youtube_playlist_id = playlist_id
                row.verified_at = _utcnow()
                row.title = (title or "")[:255]
            try:
                self.db.commit()
            except IntegrityError:
                self.db.rollback()
        if tracker is not None:
            tracker.record_playlist_created(self.user_id)
        return playlist_id

    def _resolve_playlist(
        self, title: str, playback_mode: str, headers: dict, category: str
    ) -> Tuple[str, bool]:
        """
        Return (playlist_id, created_now).

        Costs 1 unit when a cached ID needs re-verification and 0 while it is
        inside the TTL window; 50 units only when a playlist must be created.
        """
        row = self._cached_playlist_row(category)

        if row is not None and self._verification_expired(row):
            tracker = self.tracker
            if tracker is not None:
                tracker.ensure_budget(self.user_id, config.ytm_unit_cost("playlists.list"))
            if not self._verify_playlist_still_exists(row.youtube_playlist_id, headers):
                logger.info(
                    "Cached playlist %s no longer exists; creating a replacement",
                    row.youtube_playlist_id,
                )
                try:
                    self.db.delete(row)
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                row = None

        if row is not None:
            row.verified_at = _utcnow()
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
            return row.youtube_playlist_id, False

        return self._create_playlist(title, playback_mode, headers, category), True

    def _verification_expired(self, row: models.UserPlaylist) -> bool:
        if config.PLAYLIST_VERIFY_TTL_SECONDS <= 0:
            return True
        if row.verified_at is None:
            return True
        verified_at = row.verified_at
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=datetime.timezone.utc)
        return (_utcnow_aware() - verified_at).total_seconds() > config.PLAYLIST_VERIFY_TTL_SECONDS

    # ------------------------------------------------------------------ #
    # Local playlist mirror
    # ------------------------------------------------------------------ #
    def _load_mirror(self, playlist_id: str) -> set:
        if self.db is None:
            return set()
        rows = (
            self.db.query(models.PlaylistItemsCache.video_id)
            .filter_by(youtube_playlist_id=playlist_id)
            .all()
        )
        return {row[0] for row in rows}

    def _sync_mirror(self, playlist_id: str, headers: dict, mirror: set) -> int:
        """
        Rebuild the mirror with playlistItems.list (1 unit per 50 items).

        Only runs when we reused an existing playlist whose mirror is empty,
        which is the case after a fresh deploy or a manual DB reset.
        """
        if self.db is None:
            return 0

        pages = 0
        page_token = None
        while pages < min(MAX_PAGES_PER_LIST_CALL, config.PLAYLIST_SYNC_MAX_PAGES):
            pages += 1
            params = {
                "part": "contentDetails",
                "maxResults": 50,
                "playlistId": playlist_id,
                "fields": "nextPageToken,items(contentDetails(videoId))",
            }
            if page_token:
                params["pageToken"] = page_token

            action, response, body = self._request_with_retry(
                "playlistItems.list", f"{YOUTUBE_API_BASE}/playlistItems", headers=headers,
                params=params, max_retries=1,
            )
            if action == "auth":
                raise GoogleAuthError(
                    f"YouTube rejected the stored credential: {self._redact(response)}"
                )
            if action == "quota":
                raise quota.YouTubeQuotaDepleted(
                    "YouTube API quota exceeded upstream. Please try again later today."
                )
            if action != "ok":
                logger.warning(
                    "Aborting playlist mirror sync for %s: %s",
                    playlist_id, self._redact(response),
                )
                break

            discovered = 0
            for item in body.get("items", []) or []:
                video_id = (item.get("contentDetails") or {}).get("videoId")
                if video_id and video_id not in mirror:
                    mirror.add(video_id)
                    discovered += 1

            if discovered:
                self._flush_mirror(playlist_id, mirror, replace=False)

            next_token = body.get("nextPageToken")
            if not next_token or next_token == page_token:
                break
            page_token = next_token

        logger.info("Mirrored %s existing items for playlist %s", len(mirror), playlist_id)
        return pages

    def _flush_mirror(self, playlist_id: str, mirror: set, replace: bool = False) -> None:
        """
        Persist newly discovered video IDs.

        One commit per batch, and the write uses ON CONFLICT DO NOTHING so a
        concurrent worker mirroring the same playlist cannot fail the request.
        """
        if self.db is None or not mirror:
            return
        rows = [
            {"youtube_playlist_id": playlist_id, "video_id": video_id}
            for video_id in mirror
        ]
        try:
            dialect = self.db.get_bind().dialect.name
            if dialect == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as _insert

                stmt = (
                    _insert(models.PlaylistItemsCache)
                    .values(rows)
                    .on_conflict_do_nothing(
                        index_elements=[
                            models.PlaylistItemsCache.youtube_playlist_id,
                            models.PlaylistItemsCache.video_id,
                        ]
                    )
                )
            else:
                from sqlalchemy.dialects.sqlite import insert as _insert

                stmt = (
                    _insert(models.PlaylistItemsCache)
                    .values(rows)
                    .on_conflict_do_nothing(
                        index_elements=[
                            models.PlaylistItemsCache.youtube_playlist_id,
                            models.PlaylistItemsCache.video_id,
                        ]
                    )
                )
            self.db.execute(stmt)
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
        except Exception:
            self.db.rollback()
            logger.exception("Failed to persist playlist mirror for %s", playlist_id)

    # ------------------------------------------------------------------ #
    # Optional batch validation of video IDs (1 unit / 50 IDs)
    # ------------------------------------------------------------------ #
    def _validate_video_ids(self, video_ids: Sequence[str], headers: dict) -> List[str]:
        """
        Drop IDs YouTube does not recognise, using videos.list instead of
        discovering them via 50-unit failed playlistItems.insert calls.

        Off by default (YTM_VALIDATE_VIDEO_IDS) because a video that
        videos.list omits is one we would otherwise attempt to insert.
        """
        confirmed: List[str] = []
        candidates = list(video_ids)
        for start in range(0, len(candidates), 50):
            batch = candidates[start:start + 50]
            action, response, body = self._request_with_retry(
                "videos.list",
                f"{YOUTUBE_API_BASE}/videos",
                headers=headers,
                params={
                    "part": "id",
                    "id": ",".join(batch),
                    "fields": "items(id)",
                    "maxResults": 50,
                },
                max_retries=1,
            )
            if action != "ok":
                logger.warning(
                    "videos.list validation failed (%s); falling back to inserting the batch",
                    self._redact(response),
                )
                return list(video_ids)
            confirmed.extend(
                item.get("id") for item in (body.get("items") or []) if item.get("id")
            )
        return [vid for vid in video_ids if vid in set(confirmed)]

    # ------------------------------------------------------------------ #
    # Main restore pass
    # ------------------------------------------------------------------ #
    def _restore_pass(
        self,
        title: str,
        video_ids: List[str],
        playback_mode: str,
        access_token: str,
        category: Optional[str],
    ) -> Tuple[str, List[str]]:
        headers = self._headers(access_token)
        tracker = self.tracker

        playlist_id, created_now = self._resolve_playlist(title, playback_mode, headers, category)

        mirror = self._load_mirror(playlist_id)
        synced_pages = 0
        if not mirror and not created_now:
            synced_pages = self._sync_mirror(playlist_id, headers, mirror)
        if synced_pages:
            logger.info(
                "Rebuilt the local mirror for %s from %d playlistItems page(s)",
                playlist_id, synced_pages,
            )

        pending = [vid for vid in video_ids if vid not in mirror]
        logger.info(
            "Restore plan for playlist %s: %d candidate track(s), %d already mirrored, "
            "%d pending insert(s), created_now=%s",
            playlist_id, len(video_ids), len(video_ids) - len(pending), len(pending), created_now,
        )

        if not pending:
            return playlist_id, []

        # Never issue a call we already know we cannot afford. This is a
        # per-track check rather than one up-front projection: a snapshot larger
        # than a user's remaining budget is restored as far as the budget allows
        # instead of being refused whole. The caller still receives a real
        # playlist; the tracks that did not fit are reported as failed.
        insert_cost = config.ytm_unit_cost("playlistItems.insert")

        if config.FLAG_VALIDATE_VIDEO_IDS:
            # Validation costs 1 unit per 50 IDs against 50 per insert, so it is
            # worth skipping rather than letting it push us over budget.
            validate_cost = max(1, -(-len(pending) // 50)) * config.ytm_unit_cost("videos.list")
            if tracker is None or self._affordable(self.user_id, tracker, validate_cost):
                confirmed = self._validate_video_ids(pending, headers)
                if len(confirmed) != len(pending):
                    logger.info(
                        "Dropped %d unresolvable video ID(s) before insert",
                        len(pending) - len(confirmed),
                    )
                pending = confirmed
            else:
                logger.info("Skipping video ID validation: budget too small to afford it")

        failed: List[str] = []
        dirty: set = set()
        for index, video_id in enumerate(pending):
            if tracker is not None:
                try:
                    tracker.ensure_budget(self.user_id, insert_cost)
                except quota.QuotaBudgetExceeded as budget_err:
                    # Out of room. Keep what was already written and account for
                    # the rest, rather than burning units we said we would not.
                    logger.warning(
                        "Quota budget exhausted mid-restore (%s): playlist %s keeps %d/%d "
                        "track(s); %d skipped for budget",
                        budget_err.scope, playlist_id, index, len(pending),
                        len(pending) - index,
                    )
                    failed.extend(pending[index:])
                    break

            success = self._insert_track(playlist_id, video_id, headers)
            if success:
                # Update the in-memory mirror immediately so a duplicate later
                # in the same batch can never be billed twice.
                mirror.add(video_id)
                dirty.add(video_id)
            else:
                failed.append(video_id)
            if dirty and (index + 1) % CACHE_FLUSH_BATCH_SIZE == 0:
                self._flush_mirror(playlist_id, dirty, replace=False)
                dirty = set()

        if dirty:
            self._flush_mirror(playlist_id, dirty, replace=False)

        return playlist_id, failed

    def _insert_track(self, playlist_id: str, video_id: str, headers: dict) -> bool:
        action, response, _ = self._request_with_retry(
            "playlistItems.insert",
            f"{YOUTUBE_API_BASE}/playlistItems",
            headers=headers,
            json_body={
                "snippet": {
                    "playlistId": playlist_id,
                    "resourceId": {"kind": "youtube#video", "videoId": video_id},
                }
            },
            params={"part": "snippet", "fields": "id"},
            max_retries=1,
        )
        if action == "ok":
            return True
        if action == "notfound":
            # Ambiguous: could be the playlist or the video. Re-raise so the
            # caller can re-resolve the playlist once; the outer loop retries.
            raise YouTubePlaylistDeleted(
                f"playlistItems.insert returned 404 for video {video_id}"
            )
        if action == "auth":
            raise GoogleAuthError(f"YouTube rejected the stored credential: {self._redact(response)}")
        if action == "quota":
            raise quota.YouTubeQuotaDepleted(
                "YouTube API quota exceeded upstream. Please try again later today."
            )
        logger.warning(
            "Failed to append track %s to playlist %s: %s", video_id, playlist_id, self._redact(response)
        )
        return False

    # ------------------------------------------------------------------ #
    # Public entry points
    # ------------------------------------------------------------------ #
    @staticmethod
    def ordered_video_ids(tracks: List[Dict], dedupe: Optional[bool] = None) -> List[str]:
        """
        Extract video IDs from a snapshot, preserving queue order.

        When dedupe is enabled, repeated IDs inside a single snapshot collapse
        to one insert. That is 50 units saved per duplicate; it is off by
        default so a queue that deliberately lists the same song twice still
        produces a playlist that lists it twice.
        """
        if dedupe is None:
            dedupe = config.FLAG_DEDUPE_WITHIN_SNAPSHOT
        seen = set()
        ordered = []
        for track in tracks or []:
            if not isinstance(track, dict):
                continue
            video_id = track.get("videoId")
            if not isinstance(video_id, str) or not video_id:
                continue
            if dedupe:
                if video_id in seen:
                    continue
                seen.add(video_id)
            ordered.append(video_id)
        return ordered

    def restore_playlist(
        self,
        title: str,
        tracks: List[Dict],
        playback_mode: str,
        db: Session = None,
        user_id: int = None,
        category: str = None,
    ) -> str:
        """
        Materializes a saved snapshot directly into the user's YouTube Music
        personal account.

        Uses the official YouTube Data API v3 path when an access token is
        available. The ytmusicapi fallback is only reached for unexpected
        errors, never for a quota refusal or a dead credential - both of which
        would otherwise bypass the quota ledger entirely.
        """
        if db is not None:
            self.db = db
        if user_id is not None:
            self.user_id = user_id

        access_token = self.token_data.get("access_token")
        video_ids = self.ordered_video_ids(tracks)

        if access_token:
            try:
                logger.info("Attempting playlist restore via YouTube Data API v3...")
                return self._restore_via_youtube_data_api(
                    title=title,
                    video_ids=video_ids,
                    playback_mode=playback_mode,
                    access_token=access_token,
                    category=category,
                )
            except quota.QuotaBudgetExceeded as budget_err:
                # Deliberately not falling through to ytmusicapi: that path
                # would create a fresh playlist and spend quota we have just
                # refused to spend.
                logger.warning(
                    "Restore refused by quota budget (%s): %s", budget_err.scope, budget_err
                )
                raise
            except GoogleAuthError:
                logger.warning("Restore aborted: stored Google credential is no longer valid")
                raise
            except Exception as api_err:
                logger.warning(
                    "YouTube Data API restore failed (%s: %s)",
                    type(api_err).__name__,
                    api_err,
                )
                if not config.FLAG_ALLOW_YTMUSICAPI_FALLBACK:
                    raise

        return self._restore_via_ytmusicapi(title, video_ids, playback_mode)

    def _restore_via_youtube_data_api(
        self,
        title: str,
        video_ids: List[str],
        playback_mode: str,
        access_token: str,
        category: Optional[str] = None,
    ) -> str:
        access_token = self._resolve_access_token(access_token)

        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_PLAYLIST_RESOLUTION_ATTEMPTS + 1):
            try:
                playlist_id, failed = self._restore_pass(
                    title=title,
                    video_ids=video_ids,
                    playback_mode=playback_mode,
                    access_token=access_token,
                    category=category,
                )
                if failed:
                    logger.warning(
                        "Restore to playlist %s completed with %d/%d track(s) failing: %s",
                        playlist_id, len(failed), len(video_ids), failed,
                    )
                return playlist_id
            except YouTubePlaylistDeleted as err:
                last_error = err
                logger.warning(
                    "Playlist vanished mid-restore (attempt %d/%d): %s",
                    attempt, MAX_PLAYLIST_RESOLUTION_ATTEMPTS, err,
                )
                self._invalidate_playlist_cache()
                continue

        raise RuntimeError(
            "YouTube rejected the target playlist repeatedly; aborting to avoid burning quota."
        ) from last_error

    def _resolve_access_token(self, access_token: str) -> str:
        """
        Refresh proactively when the stored token is known to be expired.

A 401 mid-restore is NOT retried with a refresh: by then the request has
        already been made, and a silent refresh-then-retry loop is exactly the
        pattern that turns one quota problem into several. `main.py` deletes
        the dead token and returns the existing "please sign in" body instead.
        """
        if not _token_expired(self.token_data):
            return access_token
        refreshed = refresh_access_token(self.token_data, self.user_id)
        if refreshed and refreshed.get("access_token"):
            self.token_data.update(refreshed)
            return refreshed["access_token"]
        return access_token

    def _invalidate_playlist_cache(self) -> None:
        """Drop the cached playlist mapping so the next attempt creates a new one."""
        if self.db is None or not self.user_id:
            return
        rows = (
            self.db.query(models.UserPlaylist)
            .filter_by(user_id=self.user_id)
            .all()
        )
        for row in rows:
            self.db.delete(row)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            logger.exception("Failed to invalidate cached playlist mapping")

    # ------------------------------------------------------------------ #
    # ytmusicapi fallback
    # ------------------------------------------------------------------ #
    def _get_ytmusic_instance(self) -> Tuple[YTMusic, str]:
        """
        Creates an authenticated YTMusic client using a secure short-lived
        temporary credentials file.

        NOTE: ytmusicapi's OAuth support (OAuthCredentials/RefreshingToken) requires a
        full token set - access_token, refresh_token, scope, token_type, expires_at -
        the kind you get from a server-side authorization-code exchange. Tokens
        acquired via chrome.identity.getAuthToken() are access-token-only; Chrome
        manages refresh internally and never exposes a refresh_token to the app. So
        this fallback is only usable if token_data actually came from a full OAuth
        exchange. If it didn't, fail with a clear message instead of letting
        ytmusicapi raise an opaque TypeError deep in its own constructor.
        """
        required_fields = ("refresh_token", "scope", "token_type")
        missing = [f for f in required_fields if not self.token_data.get(f)]
        if missing:
            raise RuntimeError(
                f"Cannot use the ytmusicapi fallback: token_data is missing {missing}. "
                "This is expected when the access token came from "
                "chrome.identity.getAuthToken(), which does not provide a refresh "
                "token. The YouTube Data API v3 path (using the access_token directly) "
                "is the only usable restore path for these tokens - check why that path "
                "failed rather than relying on this fallback."
            )

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        try:
            os.chmod(temp_path, 0o600)
            with os.fdopen(fd, "w") as temp_file:
                json.dump(self.token_data, temp_file)

            yt = YTMusic(
                temp_path,
                oauth_credentials=OAuthCredentials(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                ),
            )
            return yt, temp_path
        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise RuntimeError(f"Failed to initialize YouTube Music client: {str(e)}")

    def _restore_via_ytmusicapi(
        self, title: str, video_ids: List[str], playback_mode: str
    ) -> str:
        """
        Legacy fallback.

        This path is NOT quota aware, always creates a brand-new playlist and
        always re-inserts every track, so it is disabled in production by
        default (YTM_ALLOW_YTMUSICAPI_FALLBACK).
        """
        if not config.FLAG_ALLOW_YTMUSICAPI_FALLBACK:
            raise RuntimeError(
                "YouTube Data API restore failed and the ytmusicapi fallback is disabled "
                "(YTM_ALLOW_YTMUSICAPI_FALLBACK=0)."
            )
        yt, temp_path = self._get_ytmusic_instance()
        try:
            description = f"Restored via YTM Queue Saver ({playback_mode} Mode)"
            playlist_id = yt.create_playlist(title=title, description=description)
            if video_ids:
                yt.add_playlist_items(playlist_id, video_ids)
            return playlist_id
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


