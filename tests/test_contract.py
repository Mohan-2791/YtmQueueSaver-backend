"""
Contract regression tests.

These replay the exact requests the published browser extension makes and assert
that the responses, status codes and headers are unchanged. If an assertion here
fails, the live extension has been broken.

Request shapes are taken from extension/src/background/handlers.ts:
  POST /api/auth/register  { id_token, token_data: { access_token } }
  POST /api/snapshots      { title, category, playback_mode, tracks[] }
  GET  /api/snapshots?category=
  DELETE /api/snapshots/{id}
  POST /api/restore/{id}   (Authorization: Bearer <jwt>)
  DELETE /api/account
"""

import jwt as pyjwt
import pytest

import auth as auth_module
import models
import quota
import ytm_service
from database import SessionLocal


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _snapshot_payload(
    n_tracks=2, category="SESSION_WIPE", playback_mode="SONG", video_id="dQw4w9WgXcQ"
):
    return {
        "title": "Auto-Saved Queue",
        "category": category,
        "playback_mode": playback_mode,
        "tracks": [
            {"videoId": video_id, "title": f"Track {i}", "artist": "Artist"}
            for i in range(n_tracks)
        ],
    }


def user_id_from_token(token: str) -> int:
    payload = pyjwt.decode(
        token,
        auth_module.JWT_PUBLIC_KEY,
        algorithms=[auth_module.config.JWT_ALGORITHM],
        audience=auth_module.config.JWT_AUDIENCE,
        issuer=auth_module.config.JWT_ISSUER,
    )
    return int(payload["sub"])


def give_user_a_youtube_token(user_id: int, access_token: str = "test-access-token"):
    with SessionLocal() as session:
        user = session.get(models.User, user_id)
        user.encrypted_token_json = auth_module.encrypt_tokens(
            {"access_token": access_token}, user.id
        )
        user.needs_reconnect = False
        session.commit()


def clear_user_youtube_token(user_id: int):
    with SessionLocal() as session:
        user = session.get(models.User, user_id)
        user.encrypted_token_json = ""
        session.commit()


def make_other_user(prefix="other"):
    """A second account owning one snapshot, for BOLA tests."""
    with SessionLocal() as session:
        other = models.User(
            google_id=f"{prefix}-{auth_module.audit.new_nonce()}",
            email=f"{prefix}@example.com",
            encrypted_token_json="",
        )
        session.add(other)
        session.commit()
        session.refresh(other)
        other.encrypted_token_json = auth_module.encrypt_tokens(
            {"access_token": "other-token"}, other.id
        )
        snapshot = models.PlaylistSnapshot(
            user_id=other.id,
            title="Private",
            category="SESSION_WIPE",
            playback_mode="SONG",
            tracks=[{"videoId": "dQw4w9WgXcQ", "title": "x", "artist": "y"}],
        )
        session.add(snapshot)
        session.commit()
        session.refresh(snapshot)
        return other.id, snapshot.id


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.ok = 200 <= status_code < 300
        self.text = str(self._payload)

    def json(self):
        return self._payload


class _FakeYouTubeHTTP:
    """
    Stands in for the requests.Session at the true network boundary, so quota
    reservation, retry classification, playlist caching and the local mirror
    are all exercised for real.
    """

    def __init__(self, state, playlist_id):
        self.state = state
        self.playlist_id = playlist_id

    def request(self, method, url, headers=None, json=None, params=None, timeout=None):
        method = method.upper()
        if self.state.get("force_401"):
            self.state["calls"].append(f"401:{method}")
            return _FakeResponse(401, {"error": {"errors": [{"reason": "authError"}]}})

        if url.endswith("/playlists") and method == "POST":
            self.state["calls"].append("playlists.insert")
            return _FakeResponse(200, {"id": self.playlist_id})
        if url.endswith("/playlists") and method == "GET":
            self.state["calls"].append("playlists.list")
            if self.playlist_id in self.state["deleted"]:
                return _FakeResponse(
                    404, {"error": {"errors": [{"reason": "playlistNotFound"}]}}
                )
            return _FakeResponse(200, {"items": [{"id": self.playlist_id}]})
        if url.endswith("/playlistItems") and method == "GET":
            self.state["calls"].append("playlistItems.list")
            return _FakeResponse(
                200,
                {
                    "items": [
                        {"contentDetails": {"videoId": v}} for v in sorted(self.state["items"])
                    ]
                },
            )
        if url.endswith("/playlistItems") and method == "POST":
            self.state["calls"].append("playlistItems.insert")
            video_id = json["snippet"]["resourceId"]["videoId"]
            self.state["items"].add(video_id)
            self.state["inserted"].append(video_id)
            return _FakeResponse(200, {"id": "ITEM_1"})
        if url.endswith("/videos") and method == "GET":
            self.state["calls"].append("videos.list")
            requested = (params or {}).get("id", "").split(",")
            return _FakeResponse(
                200, {"items": [{"id": v} for v in requested if v in self.state["items"]]}
            )

        self.state["calls"].append(f"unexpected:{method} {url}")
        return _FakeResponse(500, {})


_playlist_seq = 0


def stub_youtube(monkeypatch, playlist_id=None):
    """
    Replace outbound HTTP with a deterministic in-memory YouTube.

    A fresh playlist ID per call matters: the item mirror is keyed by playlist ID
    (YouTube IDs are globally unique in production, one set per user), so a
    shared ID would leak mirror state between tests.
    """
    global _playlist_seq
    if playlist_id is None:
        _playlist_seq += 1
        playlist_id = f"PL_TEST_{_playlist_seq}"

    state = {
        "items": set(),
        "inserted": [],
        "calls": [],
        "deleted": set(),
        "playlist_id": playlist_id,
    }

    monkeypatch.setattr(
        ytm_service, "_http_session", lambda: _FakeYouTubeHTTP(state, playlist_id)
    )
    return state


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #
class TestStaticRoutes:
    def test_root_shape_unchanged(self, client):
        response = client.get("/")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "online"
        assert body["service"] == "YouTube Music Queue Saver API"

    @pytest.mark.parametrize("path", ["/health", "/api/health"])
    def test_health_shape_unchanged(self, client, path):
        response = client.get(path)
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "healthy"
        assert body["database"] in ("connected", "degraded")


class TestAuthContract:
    def test_test_login_returns_token_response_shape(self, client):
        response = client.post("/api/auth/test-login")
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"access_token", "token_type", "user_id"}
        assert body["token_type"] == "bearer"
        assert isinstance(body["user_id"], int)

    def test_register_rejects_unverifiable_credential_with_401(self, client):
        response = client.post(
            "/api/auth/register",
            json={"id_token": "not-a-real-google-token", "token_data": {"access_token": "x"}},
        )
        assert response.status_code == 401
        assert "detail" in response.json()

    def test_register_rejects_unknown_top_level_fields(self, client):
        """extra=forbid: mass assignment through the request body is rejected."""
        response = client.post(
            "/api/auth/register",
            json={
                "id_token": "not-a-real-google-token",
                "token_data": {"access_token": "x"},
                "is_admin": True,
            },
        )
        assert response.status_code == 422

    def test_register_drops_non_whitelisted_token_fields(self, client, monkeypatch):
        """token_data is parsed into a whitelist before anything is stored."""
        import crypto
        import schemas

        parsed = schemas.OAuthLoginSchema(
            id_token="x",
            token_data={
                "access_token": "real",
                "refresh_token": "real-refresh",
                "evil_payload": "should-be-dropped",
                "scope": "https://www.googleapis.com/auth/youtube",
            },
        )
        stored = parsed.token_data.to_storable()
        assert stored == {
            "access_token": "real",
            "refresh_token": "real-refresh",
            "scope": "https://www.googleapis.com/auth/youtube",
        }
        assert crypto.sanitize_token_data(parsed.token_data.to_storable()) == stored


class TestAuthorization:
    def test_protected_route_without_token_is_401(self, client):
        response = client.get("/api/snapshots?category=SESSION_WIPE")
        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "Bearer"
        assert "detail" in response.json()

    def test_protected_route_with_garbage_token_is_401(self, client):
        response = client.get(
            "/api/snapshots?category=SESSION_WIPE",
            headers={"Authorization": "Bearer not.a.jwt"},
        )
        assert response.status_code == 401
        assert "detail" in response.json()

    def test_unsigned_token_is_rejected(self, client):
        """alg:none must not be accepted by an RS256 service."""
        import datetime

        forged = pyjwt.encode(
            {"sub": "1", "iss": "saveQueue", "aud": "saveQueue-client",
             "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
            key="",
            algorithm="none",
        )
        response = client.get(
            "/api/snapshots?category=SESSION_WIPE",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert response.status_code == 401


class TestSnapshotContract:
    def test_create_returns_201_with_full_object(self, client, fresh_headers):
        response = client.post("/api/snapshots", json=_snapshot_payload(), headers=fresh_headers)
        assert response.status_code == 201, response.text
        body = response.json()
        assert {
            "id", "user_id", "title", "category", "playback_mode", "tracks", "created_at"
        } == set(body)
        assert body["category"] == "SESSION_WIPE"
        assert body["playback_mode"] == "SONG"
        assert len(body["tracks"]) == 2
        assert body["tracks"][0]["videoId"] == "dQw4w9WgXcQ"

    def test_list_filters_by_category(self, client, fresh_headers):
        client.post(
            "/api/snapshots",
            json=_snapshot_payload(category="ARCHIVE_HISTORY"),
            headers=fresh_headers,
        )
        response = client.get("/api/snapshots?category=SESSION_WIPE", headers=fresh_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        assert all(item["category"] == "SESSION_WIPE" for item in response.json())

    def test_list_rejects_unknown_category(self, client, fresh_headers):
        response = client.get("/api/snapshots?category=NOPE", headers=fresh_headers)
        assert response.status_code == 422

    def test_delete_returns_204_with_empty_body(self, client, fresh_headers):
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(), headers=fresh_headers
        ).json()
        response = client.delete(f"/api/snapshots/{created['id']}", headers=fresh_headers)
        assert response.status_code == 204
        assert response.content == b""

    def test_delete_missing_snapshot_is_404(self, client, fresh_headers):
        response = client.delete("/api/snapshots/99999999", headers=fresh_headers)
        assert response.status_code == 404
        assert response.json()["detail"] == "Snapshot not found"

    def test_malformed_video_id_is_422(self, client, fresh_headers):
        payload = _snapshot_payload(1)
        payload["tracks"][0]["videoId"] = "not-a-video-id"
        response = client.post("/api/snapshots", json=payload, headers=fresh_headers)
        assert response.status_code == 422

    def test_unknown_track_field_is_rejected(self, client, fresh_headers):
        payload = _snapshot_payload(1)
        payload["tracks"][0]["playlistPosition"] = 99
        response = client.post("/api/snapshots", json=payload, headers=fresh_headers)
        assert response.status_code == 422

    def test_oversized_title_is_422(self, client, fresh_headers):
        payload = _snapshot_payload(1)
        payload["title"] = "x" * 10_000
        response = client.post("/api/snapshots", json=payload, headers=fresh_headers)
        assert response.status_code in (413, 422)

    def test_wrong_content_type_is_415(self, client, fresh_headers):
        response = client.post(
            "/api/snapshots",
            content="title=x",
            headers={**fresh_headers, "Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 415


class TestBolaAndTenantIsolation:
    def test_cannot_restore_another_users_snapshot(self, client, fresh_headers):
        _, snapshot_id = make_other_user("other-restore")
        response = client.post(f"/api/restore/{snapshot_id}", headers=fresh_headers)
        assert response.status_code == 403
        assert response.json()["detail"] == "Not authorized to restore this snapshot"

    def test_cannot_delete_another_users_snapshot(self, client, fresh_headers):
        _, snapshot_id = make_other_user("other-delete")
        response = client.delete(f"/api/snapshots/{snapshot_id}", headers=fresh_headers)
        assert response.status_code == 403

    def test_cannot_read_another_users_snapshots(self, client, fresh_headers):
        make_other_user("other-list")
        response = client.get("/api/snapshots?category=SESSION_WIPE", headers=fresh_headers)
        assert response.status_code == 200
        assert all(item["title"] != "Private" for item in response.json())


class TestRestoreContract:
    def test_missing_snapshot_is_404(self, client, fresh_headers):
        response = client.post("/api/restore/99999999", headers=fresh_headers)
        assert response.status_code == 404
        assert response.json()["detail"] == "Snapshot not found"

    def test_success_shape_is_frozen(self, client, fresh_headers, account, monkeypatch):
        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        state = stub_youtube(monkeypatch)

        response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"status", "ytm_playlist_id", "playlist_url"}
        assert body["status"] == "success"
        assert body["playlist_url"] == (
            f"https://music.youtube.com/playlist?list={body['ytm_playlist_id']}"
        )
        assert state["items"] == {"dQw4w9WgXcQ"}
        assert state["calls"] == ["playlists.insert", "playlistItems.insert"]

    def test_warm_restore_spends_zero_units(
        self, client, fresh_headers, account, monkeypatch
    ):
        """Second restore of the same snapshot must not call YouTube at all."""
        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        state = stub_youtube(monkeypatch)

        first = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert first.status_code == 200, first.text
        assert state["calls"] == ["playlists.insert", "playlistItems.insert"]

        with SessionLocal() as session:
            spent = quota.QuotaTracker(session).user_usage(account.id)
        assert spent == 100  # 50 for playlists.insert + 50 for playlistItems.insert

        state["calls"].clear()
        second = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert second.status_code == 200, second.text
        assert second.json()["ytm_playlist_id"] == first.json()["ytm_playlist_id"]
        assert state["calls"] == [], "warm re-restore must not call YouTube at all"

        with SessionLocal() as session:
            assert quota.QuotaTracker(session).user_usage(account.id) == spent

    def test_deleted_cached_playlist_is_recreated(
        self, client, fresh_headers, account, monkeypatch
    ):
        """A playlist the user removed in YouTube must not fail the restore."""
        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        state = stub_youtube(monkeypatch)

        assert client.post(f"/api/restore/{created['id']}", headers=fresh_headers).status_code == 200

        # User deletes the playlist; the TTL must expire so it is re-verified.
        state["deleted"].add(state["playlist_id"])
        state["calls"].clear()
        import config

        original_ttl = config.PLAYLIST_VERIFY_TTL_SECONDS
        config.PLAYLIST_VERIFY_TTL_SECONDS = 0
        try:
            state["items"] = set()
            response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        finally:
            config.PLAYLIST_VERIFY_TTL_SECONDS = original_ttl

        assert response.status_code == 200, response.text
        assert "playlists.list" in state["calls"]
        assert state["calls"].count("playlists.insert") == 1

    def test_no_stored_credentials_returns_400_sign_in_body(
        self, client, fresh_headers, account
    ):
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        clear_user_youtube_token(account.id)

        response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert response.status_code == 400
        assert response.json()["detail"] == (
            "User has no stored YouTube Music credentials. Please sign in with Google."
        )

    def test_dead_google_token_returns_400_sign_in_body(
        self, client, fresh_headers, account, monkeypatch
    ):
        """A 401 from YouTube must produce the existing sign-in body, not a 502."""
        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        state = stub_youtube(monkeypatch)
        state["force_401"] = True

        response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert response.status_code == 400
        assert response.json()["detail"] == (
            "User has no stored YouTube Music credentials. Please sign in with Google."
        )

        with SessionLocal() as session:
            user = session.get(models.User, account.id)
            assert user.encrypted_token_json == ""
            assert user.needs_reconnect is True

    def test_quota_exhaustion_returns_502_with_detail(
        self, client, fresh_headers, account, monkeypatch
    ):
        """The circuit breaker must look like an ordinary failure to the client."""
        import config

        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        state = stub_youtube(monkeypatch)
        monkeypatch.setattr(config, "QUOTA_GLOBAL_CAP", 0)

        response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert response.status_code == 502
        body = response.json()
        assert body["detail"].startswith("Failed to restore playlist to YouTube Music:")
        assert "quota" in body["detail"].lower()
        assert state["calls"] == [], "the breaker must trip before any YouTube call"

    def test_error_detail_does_not_leak_internals(
        self, client, fresh_headers, account, monkeypatch
    ):
        give_user_a_youtube_token(account.id)
        created = client.post(
            "/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers
        ).json()
        stub_youtube(monkeypatch)

        def raise_secret(self, *args, **kwargs):
            raise RuntimeError("postgresql://user:pw@db.internal:5432/prod")

        monkeypatch.setattr(ytm_service.YTMService, "_restore_pass", raise_secret)

        response = client.post(f"/api/restore/{created['id']}", headers=fresh_headers)
        assert response.status_code == 502
        detail = response.json()["detail"]
        assert "postgresql" not in detail
        assert "db.internal" not in detail
        assert "pw@" not in detail


class TestAccountAndLogout:
    def test_logout_returns_204_then_invalidates(self, client, fresh_headers):
        client.post("/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers)

        response = client.post("/api/auth/logout", headers=fresh_headers)
        assert response.status_code == 204
        assert response.content == b""

        after = client.get("/api/snapshots?category=SESSION_WIPE", headers=fresh_headers)
        assert after.status_code == 401
        assert after.json()["detail"] == "Session token has been revoked"

    def test_delete_account_cascades(self, client, fresh_headers, account, monkeypatch):
        monkeypatch.setattr("auth.revoke_google_token", lambda token: True)
        give_user_a_youtube_token(account.id)
        client.post("/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers)

        response = client.request("DELETE", "/api/account", headers=fresh_headers)
        assert response.status_code == 204

        with SessionLocal() as session:
            assert session.get(models.User, account.id) is None
            assert (
                session.query(models.PlaylistSnapshot)
                .filter(models.PlaylistSnapshot.user_id == account.id)
                .count()
                == 0
            )
            assert (
                session.query(models.QuotaUsage)
                .filter(models.QuotaUsage.user_id == account.id)
                .count()
                == 0
            )


class TestSecurityHeaders:
    def test_auth_responses_are_not_cacheable(self, client):
        response = client.post("/api/auth/test-login")
        assert response.headers.get("cache-control") == "no-store"
        assert response.headers.get("x-content-type-options") == "nosniff"

    def test_correlation_id_is_echoed(self, client):
        assert client.get("/health").headers.get("x-request-id")
        response = client.get("/health", headers={"X-Request-ID": "abc-123"})
        assert response.headers["x-request-id"] == "abc-123"

    def test_malicious_request_id_is_replaced(self, client):
        injected = "bad id with spaces\nX-Evil: 1"
        response = client.get("/health", headers={"X-Request-ID": injected})
        assert response.headers["x-request-id"] != injected

    def test_referrer_policy_present(self, client):
        assert client.get("/health").headers.get("referrer-policy") == "strict-origin"

    def test_framing_is_denied(self, client):
        assert client.get("/health").headers.get("x-frame-options") == "DENY"

    def test_snapshot_responses_are_not_cached(self, client, fresh_headers):
        """Snapshot payloads must not be stored by a shared proxy."""
        response = client.post("/api/snapshots", json=_snapshot_payload(1), headers=fresh_headers)
        assert response.status_code == 201
        assert response.headers.get("cache-control") == "no-store"


class TestRateLimiting:
    def test_limits_leave_headroom_for_real_usage(self):
        """
        slowapi binds its decorators at import time, so the caps themselves are
        not re-testable here. What matters is that the shipped values stay far
        above the extension's real pattern (one call per user action) while
        still refusing a flood.
        """
        import config

        assert config.RATE_LIMIT_RESTORE_PER_MIN >= 10
        assert config.RATE_RESTORE_PER_HOUR >= config.RATE_LIMIT_RESTORE_PER_MIN
        assert config.RATE_LIMIT_REGISTER_PER_MIN >= 5
        assert config.RATE_DELETE_ACCOUNT_PER_MIN >= 3
        assert config.MAX_REQUEST_BODY_BYTES > 0
