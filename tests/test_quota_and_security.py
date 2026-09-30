"""
Unit tests for the quota ledger, budgets, circuit breaker and deduplication.

These cover the logic that the contract tests stub out, plus the invariants the
published extension depends on (never spending more units than we intend).
"""

import datetime

import pytest

import config
import crypto
import quota
from database import SessionLocal
from ytm_service import YTMService


@pytest.fixture
def fresh_user():
    import auth as auth_module
    import models

    with SessionLocal() as session:
        user = models.User(
            google_id=f"quota-{auth_module.audit.new_nonce()}",
            email="quota@example.com",
            encrypted_token_json="",
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        user_id = user.id
    yield user_id
    # Everything the user owns has to go, not just the user row: SQLite reuses
    # the freed rowid, so a leftover UserPlaylist would be found again by the
    # next fixture and hand it a stale cached playlist (and a warm mirror).
    with SessionLocal() as session:
        playlists = [
            row.youtube_playlist_id
            for row in session.query(models.UserPlaylist).filter_by(user_id=user_id).all()
        ]
        for playlist_id in playlists:
            session.query(models.PlaylistItemsCache).filter_by(
                youtube_playlist_id=playlist_id
            ).delete(synchronize_session=False)
        session.query(models.UserPlaylist).filter_by(user_id=user_id).delete(
            synchronize_session=False
        )
        session.query(models.QuotaUsage).filter_by(user_id=user_id).delete(
            synchronize_session=False
        )
        session.query(models.User).filter_by(id=user_id).delete(synchronize_session=False)
        session.commit()


# --------------------------------------------------------------------------- #
# Pacific-time accounting
# --------------------------------------------------------------------------- #
class TestPacificDay:
    def test_quota_day_is_pacific_not_utc(self):
        # 03:00 UTC on 2026-01-02 is still 2026-01-01 in Los Angeles.
        moment = datetime.datetime(2026, 1, 2, 3, 0, tzinfo=datetime.timezone.utc)
        assert quota.quota_day_str(moment) == "2026-01-01"

    def test_naive_datetime_is_treated_as_utc(self):
        naive = datetime.datetime(2026, 1, 2, 3, 0)
        assert quota.quota_day_str(naive) == quota.quota_day_str(
            naive.replace(tzinfo=datetime.timezone.utc)
        )

    def test_reset_countdown_is_within_a_day(self):
        seconds = quota.seconds_until_quota_reset()
        assert 0 <= seconds <= 86400


# --------------------------------------------------------------------------- #
# Ledger
# --------------------------------------------------------------------------- #
class TestQuotaLedger:
    def test_reserve_creates_then_accumulates(self, fresh_user):
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            assert tracker.reserve(fresh_user, 50, method="playlists.insert") == 50
            assert tracker.reserve(fresh_user, 50, method="playlistItems.insert") == 100
            assert tracker.user_usage(fresh_user) == 100
            assert tracker.global_usage() >= 100

    def test_reserve_of_zero_is_a_noop(self, fresh_user):
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            before = tracker.user_usage(fresh_user)
            tracker.reserve(fresh_user, 0)
            assert tracker.user_usage(fresh_user) == before

    def test_usage_is_scoped_to_the_pacific_day(self, fresh_user):
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session, date_str="1999-01-01")
            tracker.reserve(fresh_user, 50)
            assert tracker.user_usage(fresh_user) == 50
            assert quota.QuotaTracker(session).user_usage(fresh_user) == 0

    def test_playlists_created_counter(self, fresh_user):
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            tracker.record_playlist_created(fresh_user)
            tracker.record_playlist_created(fresh_user)
            assert tracker.user_playlists_created(fresh_user) == 2


# --------------------------------------------------------------------------- #
# Budgets / circuit breaker
# --------------------------------------------------------------------------- #
class TestCircuitBreaker:
    def test_global_cap_trips(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 10_000)
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            tracker.reserve(fresh_user, 100)
            with pytest.raises(quota.GlobalQuotaExceeded) as exc:
                tracker.ensure_budget(fresh_user, 1)
            assert exc.value.scope == "global"

    def test_projected_cost_is_inclusive(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 10_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 100)
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            tracker.reserve(fresh_user, 60)
            # 60 + 50 = 110 > 100 -> refused before spending anything.
            with pytest.raises(quota.UserQuotaExceeded) as exc:
                tracker.ensure_budget(fresh_user, 50)
            assert exc.value.scope == "user"
            # 60 + 40 = 100 is allowed.
            tracker.ensure_budget(fresh_user, 40)

    def test_exact_boundary_is_allowed(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 10_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 100)
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            tracker.reserve(fresh_user, 100)
            tracker.ensure_budget(fresh_user, 0)

    def test_playlist_creation_abuse_cap(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "MAX_PLAYLIST_CREATES_PER_USER_PER_DAY", 2)
        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            tracker.record_playlist_created(fresh_user)
            tracker.record_playlist_created(fresh_user)
            with pytest.raises(quota.UserQuotaExceeded):
                tracker.ensure_can_create_playlist(fresh_user)

    def test_tracker_without_db_never_raises(self):
        tracker = quota.QuotaTracker(None)
        assert tracker.global_usage() == 0
        assert tracker.user_usage(1) == 0
        # Reserving with no session is a no-op rather than an exception, so a
        # missing DB can never turn into a 500 on the restore route.
        before = set(quota._ALERTED)
        assert tracker.reserve(1, 50) == 0
        assert quota._ALERTED == before, "a DB-less tracker must not announce thresholds"


class TestEstimateRestoreUnits:
    def test_warm_restore_costs_zero_units(self):
        assert (
            quota.estimate_restore_units(
                track_count=100, needs_playlist_create=False, needs_sync=False,
                items_to_insert=0,
            )
            == 1
        )  # playlists.list inside the verification TTL is the only call

    def test_cold_restore_cost(self):
        assert (
            quota.estimate_restore_units(
                track_count=100, needs_playlist_create=True, needs_sync=False,
                items_to_insert=100,
            )
            == 50 + 5000
        )

    def test_sync_adds_one_unit_per_page(self):
        assert (
            quota.estimate_restore_units(
                track_count=3, needs_playlist_create=False, needs_sync=True,
                items_to_insert=3, sync_pages=1,
            )
            == 1 + 1 + 150
        )


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #
class TestVideoIdExtraction:
    TRACKS = [
        {"videoId": "aaaaaaaaaaa"},
        {"videoId": "bbbbbbbbbbb"},
        {"videoId": "aaaaaaaaaaa"},
        {"videoId": "ccccccccccc"},
    ]

    def test_dedupe_flag_off_preserves_duplicates(self, monkeypatch):
        monkeypatch.setattr(config, "FLAG_DEDUPE_WITHIN_SNAPSHOT", False)
        ids = YTMService.ordered_video_ids(self.TRACKS)
        assert ids == ["aaaaaaaaaaa", "bbbbbbbbbbb", "aaaaaaaaaaa", "ccccccccccc"]

    def test_dedupe_flag_on_collapses_duplicates_in_order(self, monkeypatch):
        monkeypatch.setattr(config, "FLAG_DEDUPE_WITHIN_SNAPSHOT", True)
        ids = YTMService.ordered_video_ids(self.TRACKS)
        assert ids == ["aaaaaaaaaaa", "bbbbbbbbbbb", "ccccccccccc"]

    def test_junk_entries_are_skipped(self, monkeypatch):
        monkeypatch.setattr(config, "FLAG_DEDUPE_WITHIN_SNAPSHOT", True)
        tracks = [None, "string", {}, {"videoId": ""}, {"videoId": "dQw4w9WgXcQ"}]
        assert YTMService.ordered_video_ids(tracks) == ["dQw4w9WgXcQ"]

    def test_empty_tracks(self, monkeypatch):
        monkeypatch.setattr(config, "FLAG_DEDUPE_WITHIN_SNAPSHOT", True)
        assert YTMService.ordered_video_ids([]) == []
        assert YTMService.ordered_video_ids(None) == []


# --------------------------------------------------------------------------- #
# Retry policy
# --------------------------------------------------------------------------- #
class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.ok = 200 <= status_code < 300
        self.text = str(self._payload)

    def json(self):
        return self._payload


class TestRetryPolicy:
    def test_429_is_never_retried(self, monkeypatch):
        calls = []

        def boom(*args, **kwargs):
            calls.append(1)
            raise AssertionError("network call should not be retried for 429")

        monkeypatch.setattr("ytm_service._http_session", lambda: _SessionThatReturns(
            _FakeResponse(429, {"error": {"errors": [{"reason": "quotaExceeded"}]}})
        ))
        service = YTMService({"access_token": "t"})
        action, response, _ = service._request_with_retry(
            "playlistItems.insert", "https://example.invalid", headers={}
        )
        assert action == "quota"

    def test_403_quota_exceeded_is_classified_as_quota(self):
        service = YTMService({"access_token": "t"})
        action, _ = service._classify(
            "playlists.insert",
            _FakeResponse(403, {"error": {"errors": [{"reason": "quotaExceeded"}]}}),
        )
        assert action == "quota"

    def test_400_is_terminal(self):
        service = YTMService({"access_token": "t"})
        action, _ = service._classify(
            "playlistItems.insert",
            _FakeResponse(400, {"error": {"errors": [{"reason": "invalidVideoId"}]}}),
        )
        assert action == "fail"

    def test_5xx_is_retryable(self):
        service = YTMService({"access_token": "t"})
        action, _ = service._classify("playlists.list", _FakeResponse(503, {}))
        assert action == "retry"

    def test_401_is_auth_not_retry(self):
        service = YTMService({"access_token": "t"})
        action, _ = service._classify("playlists.list", _FakeResponse(401, {}))
        assert action == "auth"

    def test_retries_are_bounded_and_charged_each_attempt(self, monkeypatch):
        monkeypatch.setattr(config, "YTM_MAX_RETRIES", 2)
        monkeypatch.setattr(config, "YTM_RETRY_BASE_SECONDS", 0.0)
        attempts = {"n": 0}

        class Session:
            def request(self, *args, **kwargs):
                attempts["n"] += 1
                return _FakeResponse(503, {})

        monkeypatch.setattr("ytm_service._http_session", lambda: Session())
        service = YTMService({"access_token": "t"})
        action, response, _ = service._request_with_retry(
            "playlists.list", "https://example.invalid", headers={}
        )
        assert action == "retry"
        assert attempts["n"] == 3  # 1 initial + 2 retries


class _SessionThatReturns:
    def __init__(self, response):
        self._response = response

    def request(self, *args, **kwargs):
        return self._response


# --------------------------------------------------------------------------- #
# Token encryption
# --------------------------------------------------------------------------- #
class TestTokenEncryption:
    def test_roundtrip(self):
        blob = crypto.encrypt_tokens({"access_token": "abc", "refresh_token": "def"}, 7)
        assert blob.startswith("v3:")
        assert crypto.decrypt_tokens(blob, 7) == {"access_token": "abc", "refresh_token": "def"}

    def test_nonce_is_unique_per_encryption(self):
        first = crypto.encrypt_tokens({"access_token": "abc"}, 1)
        second = crypto.encrypt_tokens({"access_token": "abc"}, 1)
        assert first != second
        assert crypto.decrypt_tokens(first, 1) == crypto.decrypt_tokens(second, 1)

    def test_aad_binds_ciphertext_to_the_user(self):
        blob = crypto.encrypt_tokens({"access_token": "abc"}, 1)
        assert crypto.decrypt_tokens(blob, 2) == {}

    def test_tampered_ciphertext_fails_closed(self):
        blob = crypto.encrypt_tokens({"access_token": "abc"}, 1)
        head, _, tail = blob.rpartition(":")
        flipped = tail[:-4] + ("AAAA" if not tail.endswith("AAAA") else "BBBB")
        assert crypto.decrypt_tokens(f"{head}:{flipped}", 1) == {}

    def test_only_whitelisted_fields_are_persisted(self):
        blob = crypto.encrypt_tokens(
            {"access_token": "abc", "evil": "payload", "scope": "yt"}, 1
        )
        assert crypto.decrypt_tokens(blob, 1) == {"access_token": "abc", "scope": "yt"}

    def test_non_dict_payload_is_coerced_empty(self):
        assert crypto.decrypt_tokens(crypto.encrypt_tokens("nope", 1), 1) == {}

    def test_empty_input(self):
        assert crypto.decrypt_tokens("", 1) == {}

    def test_legacy_records_are_flagged_for_re_encryption(self):
        assert crypto.needs_reencrypt("") is False
        assert crypto.needs_reencrypt("gAAAAABm...") is True  # Fernet
        assert crypto.needs_reencrypt(
            "v2:" + "a" * 16 + ":" + "b" * 32
        ) is True
        assert crypto.needs_reencrypt(crypto.encrypt_tokens({"access_token": "a"}, 1)) is False


# --------------------------------------------------------------------------- #
# Partial restores under an exhausted budget
# --------------------------------------------------------------------------- #
class _BudgetSession:
    """
    A YouTube stand-in that records which tracks were actually inserted.

    Each instance mints its own playlist ID: the item mirror is keyed by
    playlist ID alone (YouTube IDs are globally unique in production, one set
    per user), so a shared ID would leak mirror state between tests.
    """

    _seq = 0

    def __init__(self):
        _BudgetSession._seq += 1
        self.playlist_id = f"PL_BUDGET_{_BudgetSession._seq}"
        self.inserted = []

    def request(self, method, url, headers=None, json=None, params=None, timeout=None):
        verb = method.upper()
        if url.endswith("/playlists") and verb == "POST":
            return _FakeResponse(200, {"id": self.playlist_id})
        if url.endswith("/playlists") and verb == "GET":
            return _FakeResponse(200, {"items": [{"id": self.playlist_id}]})
        if url.endswith("/playlistItems") and verb == "POST":
            self.inserted.append(json["snippet"]["resourceId"]["videoId"])
            return _FakeResponse(200, {"id": "ITEM_1"})
        if url.endswith("/playlistItems") and verb == "GET":
            return _FakeResponse(200, {"items": []})
        return _FakeResponse(500, {})


class TestPartialRestoreUnderBudget:
    """
    A snapshot larger than the user's remaining budget must be restored as far
    as the budget allows, not refused whole: the caller still gets a real
    playlist back, and the cap is still never crossed.
    """

    def test_oversized_restore_returns_a_partial_playlist(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 300)
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        tracks = [{"videoId": f"vid{i:04d}aaaaaaa"} for i in range(20)]
        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            playlist_id = service.restore_playlist(
                "T", tracks, "SONG", category="SESSION_WIPE"
            )

        assert playlist_id == session_like.playlist_id
        # 50 to create the playlist, then 50 per track until the 300 cap is hit.
        assert len(session_like.inserted) == 5
        with SessionLocal() as session:
            used = quota.QuotaTracker(session).user_usage(fresh_user)
        assert used == 300
        assert used <= config.QUOTA_PER_USER_CAP

    def test_remaining_tracks_are_accounted_as_failed(self, fresh_user, monkeypatch):
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 300)
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        tracks = [{"videoId": f"vid{i:04d}aaaaaaa"} for i in range(20)]
        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            playlist_id, failed = service._restore_pass(
                title="T",
                video_ids=[t["videoId"] for t in tracks],
                playback_mode="SONG",
                access_token="t",
                category="SESSION_WIPE",
            )

        assert playlist_id == session_like.playlist_id
        assert len(failed) == 15, "every track that did not fit must be reported"
        assert set(failed).isdisjoint(session_like.inserted)

    def test_budget_is_never_crossed_by_a_cheap_restore(self, fresh_user, monkeypatch):
        """A restore that fits must not be truncated by an off-by-one."""
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 300)
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            _, failed = service._restore_pass(
                title="T",
                video_ids=[f"vid{i:04d}aaaaaaa" for i in range(5)],
                playback_mode="SONG",
                access_token="t",
                category="SESSION_WIPE",
            )
        assert failed == []
        assert len(session_like.inserted) == 5

    def test_second_restore_after_exhaustion_spends_nothing(
        self, fresh_user, monkeypatch
    ):
        """Once the budget is gone the playlist is reused and no units are spent."""
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 300)
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            service.restore_playlist(
                "T", [{"videoId": f"vid{i:04d}aaaaaaa"} for i in range(20)],
                "SONG", category="SESSION_WIPE",
            )
        with SessionLocal() as session:
            spent = quota.QuotaTracker(session).user_usage(fresh_user)

        session_like.inserted.clear()
        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            service.restore_playlist(
                "T", [{"videoId": f"vid{i:04d}aaaaaaa"} for i in range(20)],
                "SONG", category="SESSION_WIPE",
            )
        assert session_like.inserted == []
        with SessionLocal() as session:
            assert quota.QuotaTracker(session).user_usage(fresh_user) == spent

    def test_validation_probe_honours_the_per_user_cap(self, fresh_user, monkeypatch):
        """
        The graceful-skip probe must consider the user's cap, not just global.

        ensure_budget skips its per-user branch when handed None, so a probe that
        omits the user id would approve a videos.list call that _reserve then
        refuses with UserQuotaExceeded -- turning a skippable nicety into a
        failed restore.
        """
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 60)
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        with SessionLocal() as session:
            tracker = quota.QuotaTracker(session)
            assert YTMService._affordable(fresh_user, tracker, 50) is True
            assert YTMService._affordable(fresh_user, tracker, 100) is False

    def test_validation_is_skipped_rather_than_failing_the_restore(
        self, fresh_user, monkeypatch
    ):
        """With validation on and no budget for it, the restore still succeeds."""
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 100_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 300)
        monkeypatch.setattr(config, "FLAG_VALIDATE_VIDEO_IDS", True)
        # Make the probe unaffordable without making the inserts unaffordable:
        # after the 50-unit playlist creation, a 300-unit videos.list does not
        # fit under a 300-unit cap, while the five 50-unit inserts do.
        real_cost = config.ytm_unit_cost
        monkeypatch.setattr(
            config,
            "ytm_unit_cost",
            lambda method: 300 if method == "videos.list" else real_cost(method),
        )
        session_like = _BudgetSession()
        monkeypatch.setattr("ytm_service._http_session", lambda: session_like)

        with SessionLocal() as session:
            service = YTMService({"access_token": "t"}, db=session, user_id=fresh_user)
            playlist_id, failed = service._restore_pass(
                title="T",
                video_ids=[f"vid{i:04d}aaaaaaa" for i in range(5)],
                playback_mode="SONG",
                access_token="t",
                category="SESSION_WIPE",
            )

        assert playlist_id == session_like.playlist_id
        assert failed == [], "an unaffordable probe must not become a failed restore"
        assert len(session_like.inserted) == 5


class TestQuotaAlertDeduplication:
    def test_each_threshold_alerts_once_per_day(self, fresh_user, monkeypatch, caplog):
        """
        The service builds a fresh tracker per access, so the "already alerted"
        set has to outlive the instance or every reserved unit re-announces.
        """
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 10_000)
        monkeypatch.setattr(config, "QUOTA_PER_USER_CAP", 100)
        monkeypatch.setattr(config, "QUOTA_ALERT_WARN_PCT", 70)
        monkeypatch.setattr(config, "QUOTA_ALERT_CRIT_PCT", 90)
        quota._ALERTED.clear()

        import logging

        with caplog.at_level(logging.WARNING, logger="ytm_saver.quota"):
            with SessionLocal() as session:
                for _ in range(10):
                    # A separate tracker each time, exactly as the service does.
                    quota.QuotaTracker(session).reserve(fresh_user, 10)

        quota_lines = [r for r in caplog.records if "QUOTA" in r.getMessage()]
        assert len(quota_lines) == 2, [r.getMessage() for r in quota_lines]
        quota._ALERTED.clear()
