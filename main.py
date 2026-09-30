import logging
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import audit
import auth
import config
import migrations
import models
import quota
import schemas
from database import Base, engine, get_db
from ytm_service import GoogleAuthError, YTMService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ytm_saver")

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="YouTube Music Queue Saver API",
    version="1.1.0",
    docs_url="/docs" if not auth.IS_PRODUCTION else None,
    redoc_url="/redoc" if not auth.IS_PRODUCTION else None,
    # SECURITY: hiding the Swagger/ReDoc UI still left the raw OpenAPI schema
    # (full route map, models, field constraints) served at /openapi.json by
    # default. Disable it the same way in production.
    openapi_url="/openapi.json" if not auth.IS_PRODUCTION else None,
)

# --- Additive schema migrations ----------------------------------------------
# create_all() only creates *missing tables*. New columns and indexes need the
# idempotent migration runner. Failure here must not stop the service: every
# column added by these migrations is nullable or defaulted.
try:
    with engine.connect() as _conn:
        _session = Session(bind=_conn, autoflush=False, autocommit=False)
        try:
            migrations.apply_migrations(_session)
        finally:
            _session.close()
except Exception:  # pragma: no cover
    logger.exception("Schema migration pass failed; continuing with the existing schema")


# --- Rate limiting -----------------------------------------------------------
# Basic protection for the auth endpoints and the YouTube-API-fanning-out
# restore endpoint. Limits are per client IP and are unchanged for the
# published extension's actual usage pattern (one call per user action).
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --- CORS --------------------------------------------------------------------
# SECURITY: an origin must match the allowlist EXACTLY. A previous version used
# `origin.startswith(allowed)`, which let any origin sharing a prefix with a
# legitimate one through (e.g. a look-alike extension id ending in the same 20
# characters). The regex form is retained only as an explicit opt-in for dev,
# where unpacked extension ids differ per machine.
_DEV_DEFAULT_ORIGIN_REGEX = r"^chrome-extension://[a-z0-9]{32,40}$"
_env_origin_regex = config.ALLOWED_ORIGIN_REGEX

if auth.IS_PRODUCTION:
    ALLOWED_ORIGIN_REGEX = _env_origin_regex or None
else:
    ALLOWED_ORIGIN_REGEX = (
        _env_origin_regex if _env_origin_regex is not None else _DEV_DEFAULT_ORIGIN_REGEX
    )

ALLOWED_ORIGINS = config.ALLOWED_ORIGINS

if auth.IS_PRODUCTION and not ALLOWED_ORIGINS and not ALLOWED_ORIGIN_REGEX:
    logger.error(
        "Neither ALLOWED_ORIGINS nor ALLOWED_ORIGIN_REGEX is set. Every browser-based "
        "request (including the published extension) will be blocked by CORS. Set "
        "ALLOWED_ORIGINS=chrome-extension://<YOUR_EXTENSION_ID>."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_origin_regex=ALLOWED_ORIGIN_REGEX if ALLOWED_ORIGIN_REGEX else None,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS", "PUT", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


# --- Origin allowlist helpers -------------------------------------------------
def _origin_allowed(origin: str) -> bool:
    import re

    if origin in ALLOWED_ORIGINS:
        return True
    if ALLOWED_ORIGIN_REGEX:
        try:
            return bool(re.match(ALLOWED_ORIGIN_REGEX, origin))
        except re.error:
            return False
    return False


def _host_allowed(host: str) -> bool:
    if not config.ALLOWED_HOSTS:
        return True
    return any(host == allowed or host.endswith("." + allowed) for allowed in config.ALLOWED_HOSTS)


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _check_content_type(request: Request) -> Optional[JSONResponse]:
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type and content_type not in config.ALLOWED_JSON_CONTENT_TYPES:
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={"detail": "Unsupported Media Type"},
        )
    return None


# Paths whose responses carry a user's own data (auth material, account state,
# saved snapshots). RFC 9111 already forbids a shared cache from reusing an
# authorized response, but "no-store" states that explicitly and also covers
# browser disk caches. Health and root are public and stay cacheable.
_PUBLIC_PATHS = frozenset({"/", "/health", "/api/health"})


def _is_private_path(path: str) -> bool:
    return path not in _PUBLIC_PATHS


@app.middleware("http")
async def harden_request(request: Request, call_next):
    """
    Cross-cutting request hardening.

    Order matters: correlation id first (so every later log line is traceable),
    then cheap rejections that never reach application code.
    """
    correlation_id = audit.set_correlation_id(request.headers.get("x-request-id"))

    host = request.headers.get("host", "")
    if not _host_allowed(host):
        audit.security_event(
            "request.bad_host", outcome="denied", host=host, path=request.url.path
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content={"detail": "Invalid Host header"}
        )

    if request.method in _MUTATING_METHODS:
        # Body size cap. Applied to every mutating method regardless of
        # Content-Type: checking it only for JSON left a trivial bypass.
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > config.MAX_REQUEST_BODY_BYTES:
                    audit.security_event(
                        "request.body_too_large",
                        outcome="denied",
                        size=content_length,
                        path=request.url.path,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Payload Too Large"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid Content-Length"},
                )

        unsupported = _check_content_type(request)
        if unsupported is not None:
            return unsupported

        # Origin / CSRF. The published extension cannot send a custom header,
        # so this stays log-only until ALLOWED_ORIGINS is confirmed correct.
        origin = request.headers.get("origin") or request.headers.get("referer")
        if origin:
            if _origin_allowed(origin):
                logger.debug("Origin accepted for %s %s", request.method, request.url.path)
            else:
                audit.security_event(
                    "request.origin_rejected",
                    outcome="denied",
                    origin=origin,
                    path=request.url.path,
                )
                if config.FLAG_ENFORCE_ORIGIN:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Forbidden"}
                    )
        else:
            logger.debug(
                "No Origin/Referer header on %s %s", request.method, request.url.path
            )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Request-ID"] = correlation_id
    response.headers["Referrer-Policy"] = "strict-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if config.ENABLE_HSTS:
        response.headers["Strict-Transport-Security"] = (
            f"max-age={config.HSTS_MAX_AGE}; includeSubDomains"
        )
    if config.ENABLE_CSP:
        response.headers["Content-Security-Policy"] = config.CSP_VALUE
    if _is_private_path(request.url.path):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Last-resort handler.

    Keeps the existing `{"detail": ...}` error shape the extension already
    parses while guaranteeing no stack trace, SQL fragment or internal hostname
    reaches the client.
    """
    correlation_id = audit.get_correlation_id()
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    audit.security_event(
        "request.unhandled_exception",
        outcome="error",
        path=request.url.path,
        error=type(exc).__name__,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
        headers={"X-Request-ID": correlation_id},
    )


# --- Service metadata ---------------------------------------------------------
@app.get("/")
def root():
    return {
        "status": "online",
        "service": "YouTube Music Queue Saver API",
        "version": "1.1.0",
    }


@app.get("/health")
@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(models.User.__table__.select().limit(1))
        db_status = "connected"
    except Exception as e:
        logger.error("Health check DB connection failed: %s", e)
        db_status = "degraded"

    return {"status": "healthy", "database": db_status}


# --- Auth ---------------------------------------------------------------------
@app.post("/api/auth/register", response_model=schemas.TokenResponseSchema)
@limiter.limit(f"{config.RATE_LIMIT_REGISTER_PER_MIN}/minute")
def register_user(request: Request, payload: schemas.OAuthLoginSchema, db: Session = Depends(get_db)):
    google_payload = auth.verify_google_token(payload.id_token)
    google_id = google_payload["sub"]
    email = (google_payload.get("email") or "")[:255] or None

    user = db.query(models.User).filter(models.User.google_id == google_id).first()
    if not user:
        user = models.User(google_id=google_id, email=email, encrypted_token_json="")
        db.add(user)
        db.commit()
        db.refresh(user)

    # Only whitelisted OAuth fields are persisted.
    user.encrypted_token_json = auth.encrypt_tokens(payload.token_data.to_storable(), user.id)
    if email:
        user.email = email
    user.needs_reconnect = False
    user.last_seen_at = None

    db.commit()
    db.refresh(user)

    access_token = auth.create_access_token(user.id)
    audit.audit("auth.login", user_id=user.id, outcome="ok", method="register")
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}


@app.post("/api/auth/test-login", response_model=schemas.TokenResponseSchema)
@limiter.limit(f"{config.RATE_LIMIT_TEST_LOGIN_PER_MIN}/minute")
def test_login(request: Request, db: Session = Depends(get_db)):
    if auth.IS_PRODUCTION:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    user = db.query(models.User).filter(models.User.google_id == "local_dev_user").first()
    if not user:
        user = models.User(
            google_id="local_dev_user",
            email="dev_user@ytm-saver.local",
            encrypted_token_json="",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    user.encrypted_token_json = auth.encrypt_tokens({}, user.id)
    user.needs_reconnect = False
    db.commit()
    db.refresh(user)

    access_token = auth.create_access_token(user.id)
    audit.audit("auth.login", user_id=user.id, outcome="ok", method="test_login")
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(f"{config.RATE_LIMIT_LOGOUT_PER_MIN}/minute")
def logout(
    request: Request,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    """
    Server-side logout. ADDITIVE - the published extension never calls this, so
    its behaviour is unchanged; it exists so a session can be invalidated before
    the JWT would otherwise expire.
    """
    auth.revoke_session(db, current_user, reason="logout")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Snapshots ----------------------------------------------------------------
@app.post("/api/snapshots", response_model=schemas.SnapshotResponseSchema, status_code=status.HTTP_201_CREATED)
@limiter.limit(f"{config.RATE_RESTORE_PER_HOUR}/hour")
def create_snapshot(
    request: Request,
    payload: schemas.SnapshotCreateSchema,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    # Only the schema's declared fields are copied - never a spread of the
    # request body into the ORM model.
    tracks_json = [track.model_dump() for track in payload.tracks]

    snapshot = models.PlaylistSnapshot(
        user_id=current_user.id,
        title=payload.title,
        category=payload.category,
        playback_mode=payload.playback_mode,
        tracks=tracks_json,
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


@app.get("/api/snapshots", response_model=List[schemas.SnapshotResponseSchema])
def get_snapshots(
    category: str = Query(..., pattern="^(SESSION_WIPE|ARCHIVE_HISTORY)$"),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    # Tenant scoping is enforced in the query itself, not by a post-filter.
    snapshots = (
        db.query(models.PlaylistSnapshot)
        .filter(
            models.PlaylistSnapshot.user_id == current_user.id,
            models.PlaylistSnapshot.category == category,
        )
        .order_by(models.PlaylistSnapshot.created_at.desc())
        .all()
    )
    return snapshots


@app.delete("/api/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_snapshot(
    snapshot_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    snapshot = db.query(models.PlaylistSnapshot).filter(models.PlaylistSnapshot.id == snapshot_id).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if snapshot.user_id != current_user.id:
        audit.security_event(
            "snapshot.delete_denied",
            user_id=current_user.id,
            outcome="denied",
            snapshot_id=snapshot_id,
        )
        raise HTTPException(status_code=403, detail="Not authorized to delete this snapshot")

    db.delete(snapshot)
    db.commit()


# --- Account ------------------------------------------------------------------
@app.delete("/api/account", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(f"{config.RATE_DELETE_ACCOUNT_PER_MIN}/minute")
def delete_account(
    request: Request,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    tokens = auth.decrypt_tokens(current_user.encrypted_token_json, current_user.id)
    if tokens:
        token_to_revoke = tokens.get("access_token") or tokens.get("refresh_token")
        if token_to_revoke:
            revoked = auth.revoke_google_token(token_to_revoke)
            audit.audit(
                "account.token_revoked",
                user_id=current_user.id,
                outcome="ok" if revoked else "error",
            )

    # Manually delete caches linked by playlist ID to ensure complete cascade
    user_playlists = db.query(models.UserPlaylist).filter_by(user_id=current_user.id).all()
    playlist_ids = [up.youtube_playlist_id for up in user_playlists]
    for playlist_id in playlist_ids:
        db.query(models.PlaylistItemsCache).filter_by(youtube_playlist_id=playlist_id).delete()
    db.query(models.UserPlaylist).filter_by(user_id=current_user.id).delete()
    db.query(models.QuotaUsage).filter_by(user_id=current_user.id).delete()

    # Revoke the presented session too, so the JWT dies with the account.
    auth.revoke_session(db, current_user, reason="account_deleted")

    db.delete(current_user)
    db.commit()
    audit.audit("account.deleted", user_id=current_user.id, outcome="ok")


# --- Restore ------------------------------------------------------------------
_QUOTA_MESSAGES = {
    "global": "The shared daily YouTube API quota is exhausted. Please try again later today.",
    "user": "Your personal daily YouTube API quota is exhausted. Please try again later today.",
    "upstream": "YouTube has temporarily throttled this service. Please try again later today.",
    "quota": "The daily YouTube API quota is exhausted. Please try again later today.",
}


def _quota_detail(error: quota.QuotaBudgetExceeded) -> str:
    return _QUOTA_MESSAGES.get(error.scope, _QUOTA_MESSAGES["quota"])


@app.post("/api/restore/{snapshot_id}")
@limiter.limit(f"{config.RATE_LIMIT_RESTORE_PER_MIN}/minute")
@limiter.limit(f"{config.RATE_RESTORE_PER_HOUR}/hour")
def restore_snapshot(
    request: Request,
    snapshot_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    snapshot = db.query(models.PlaylistSnapshot).filter(models.PlaylistSnapshot.id == snapshot_id).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if snapshot.user_id != current_user.id:
        audit.security_event(
            "restore.denied",
            user_id=current_user.id,
            outcome="denied",
            snapshot_id=snapshot_id,
        )
        raise HTTPException(status_code=403, detail="Not authorized to restore this snapshot")

    tokens = auth.decrypt_tokens(current_user.encrypted_token_json, current_user.id)

    # Lazy migration: re-encrypt on first read if the record predates the
    # current envelope format, so no user is logged out by a deploy.
    if auth.needs_reencrypt(current_user.encrypted_token_json) and tokens:
        current_user.encrypted_token_json = auth.encrypt_tokens(tokens, current_user.id)
        db.commit()

    if not tokens:
        raise HTTPException(
            status_code=400,
            detail="User has no stored YouTube Music credentials. Please sign in with Google.",
        )

    ytm = YTMService(token_data=tokens, db=db, user_id=current_user.id)

    try:
        ytm_playlist_id = ytm.restore_playlist(
            title=snapshot.title,
            tracks=snapshot.tracks,
            playback_mode=snapshot.playback_mode,
            db=db,
            user_id=current_user.id,
            category=snapshot.category,
        )
        playlist_url = f"https://music.youtube.com/playlist?list={ytm_playlist_id}"
        audit.audit(
            "restore.success",
            user_id=current_user.id,
            outcome="ok",
            snapshot_id=snapshot_id,
            playlist_id=ytm_playlist_id,
            youtube_calls=ytm._tracked_methods,
        )
        return {
            "status": "success",
            "ytm_playlist_id": ytm_playlist_id,
            "playlist_url": playlist_url,
        }
    except quota.QuotaBudgetExceeded as quota_err:
        # Returned in the exact shape the extension already handles: 502 plus a
        # `detail` string. The circuit breaker must not look like a new failure
        # mode to the client.
        logger.warning(
            "Restore refused for snapshot %s (user %s): scope=%s usage=%s cap=%s",
            snapshot_id, current_user.id, quota_err.scope, quota_err.usage, quota_err.cap,
        )
        audit.security_event(
            "restore.refused_quota",
            user_id=current_user.id,
            outcome="denied",
            scope=quota_err.scope,
            usage=quota_err.usage,
            cap=quota_err.cap,
            reset_in_seconds=quota.seconds_until_quota_reset(),
        )
        raise HTTPException(
            status_code=config.QUOTA_EXCEEDED_HTTP_STATUS,
            detail=f"Failed to restore playlist to YouTube Music: {_quota_detail(quota_err)}",
        )
    except GoogleAuthError as auth_err:
        logger.warning(
            "Restore for snapshot %s rejected by Google: %s", snapshot_id, auth_err
        )
        auth.mark_needs_reconnect(db, current_user, reason="data_api_401")
        raise HTTPException(
            status_code=400,
            detail="User has no stored YouTube Music credentials. Please sign in with Google.",
        )
    except Exception as e:
        logger.exception(
            "Failed to restore snapshot %s for user %s: %s", snapshot_id, current_user.id, e
        )
        audit.security_event(
            "restore.failed",
            user_id=current_user.id,
            outcome="error",
            snapshot_id=snapshot_id,
            error=type(e).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Failed to restore playlist to YouTube Music: "
            "an unexpected error occurred while talking to YouTube.",
        )
