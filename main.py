import os
import logging
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import engine, Base, get_db
import models
import schemas
import auth
from ytm_service import YTMService

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

# --- Rate limiting -----------------------------------------------------------
# Basic protection for the auth endpoints and the YouTube-API-fanning-out
# restore endpoint. Limits are per client IP.
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- CORS ---------------------------------------------------------------
# SECURITY: previously this always defaulted to a regex matching ANY
# chrome-extension:// origin (32-40 lowercase alphanumeric chars) whenever
# ALLOWED_ORIGIN_REGEX wasn't explicitly set to empty. That's convenient in
# dev (unpacked extension IDs differ per machine) but meant the safe
# behavior in production depended on every deployer remembering to override
# it. Now the permissive default only applies when not running in
# production; production defaults to no regex (None) unless one is
# explicitly provided, and relies on ALLOWED_ORIGINS with the exact,
# published extension ID instead.
_DEV_DEFAULT_ORIGIN_REGEX = r"^chrome-extension://[a-z0-9]{32,40}$"
_env_origin_regex = os.getenv("ALLOWED_ORIGIN_REGEX")

if auth.IS_PRODUCTION:
    ALLOWED_ORIGIN_REGEX = _env_origin_regex or None
else:
    ALLOWED_ORIGIN_REGEX = _env_origin_regex if _env_origin_regex is not None else _DEV_DEFAULT_ORIGIN_REGEX

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_origin_regex=ALLOWED_ORIGIN_REGEX if ALLOWED_ORIGIN_REGEX else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS", "PUT", "PATCH"],
    allow_headers=["*"],
)


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


@app.post("/api/auth/register", response_model=schemas.TokenResponseSchema)
@limiter.limit("5/minute")
def register_user(request: Request, payload: schemas.OAuthLoginSchema, db: Session = Depends(get_db)):
    google_payload = auth.verify_google_token(payload.id_token)
    google_id = google_payload["sub"]
    email = google_payload.get("email")

    encrypted_tokens = auth.encrypt_tokens(payload.token_data)
    user = db.query(models.User).filter(models.User.google_id == google_id).first()

    if not user:
        user = models.User(google_id=google_id, email=email, encrypted_token_json=encrypted_tokens)
        db.add(user)
    else:
        user.encrypted_token_json = encrypted_tokens
        user.email = email or user.email

    db.commit()
    db.refresh(user)

    access_token = auth.create_access_token(user.id)
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}


@app.post("/api/auth/test-login", response_model=schemas.TokenResponseSchema)
@limiter.limit("10/minute")
def test_login(request: Request, db: Session = Depends(get_db)):
    if auth.IS_PRODUCTION:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    user = db.query(models.User).filter(models.User.google_id == "local_dev_user").first()
    if not user:
        user = models.User(
            google_id="local_dev_user",
            email="dev_user@ytm-saver.local",
            encrypted_token_json=auth.encrypt_tokens({}),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token = auth.create_access_token(user.id)
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}


@app.post("/api/snapshots", response_model=schemas.SnapshotResponseSchema, status_code=status.HTTP_201_CREATED)
def create_snapshot(
    payload: schemas.SnapshotCreateSchema,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    tracks_json = [t.model_dump() for t in payload.tracks]

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
        raise HTTPException(status_code=403, detail="Not authorized to delete this snapshot")

    db.delete(snapshot)
    db.commit()


@app.post("/api/restore/{snapshot_id}")
@limiter.limit("10/minute")
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
        raise HTTPException(status_code=403, detail="Not authorized to restore this snapshot")

    tokens = auth.decrypt_tokens(current_user.encrypted_token_json)
    if not tokens:
        raise HTTPException(
            status_code=400,
            detail="User has no stored YouTube Music credentials. Please sign in with Google.",
        )

    ytm = YTMService(token_data=tokens)

    try:
        ytm_playlist_id = ytm.restore_playlist(
            title=snapshot.title,
            tracks=snapshot.tracks,
            playback_mode=snapshot.playback_mode,
        )
        playlist_url = f"https://music.youtube.com/playlist?list={ytm_playlist_id}"
        return {
            "status": "success",
            "ytm_playlist_id": ytm_playlist_id,
            "playlist_url": playlist_url,
        }
    except Exception as e:
        logger.exception("Failed to restore snapshot %s for user %s: %s", snapshot_id, current_user.id, e)
        raise HTTPException(
            status_code=502,
            detail=f"Failed to restore playlist to YouTube Music: {str(e)}",
        )