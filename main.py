import os
import logging
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import engine, Base, get_db
import models
import schemas
import auth
from ytm_service import YTMService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ytm_saver")

# Initialize database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="YouTube Music Queue Saver Enterprise API",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# --- Production CORS Configuration -----------------------------------------
# Supports Chrome Extensions via regex and custom production web domains.
#
# SECURITY NOTE: the wildcard regex below (`chrome-extension://.*`) matches
# ANY installed Chrome extension, not just this project's. Combined with
# allow_credentials=True, that means any extension a user has installed
# could make authenticated requests to this API. Once you have a published
# extension ID, set ALLOWED_ORIGIN_REGEX to pin it to that exact ID, e.g.
#   ALLOWED_ORIGIN_REGEX=^chrome-extension://abcdefghijklmnopabcdefghijklmnop$
ALLOWED_ORIGIN_REGEX = os.getenv("ALLOWED_ORIGIN_REGEX", r"^chrome-extension://.*$")
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

if auth.IS_PRODUCTION and ALLOWED_ORIGIN_REGEX == r"^chrome-extension://.*$":
    logger.warning(
        "Running in production with the default wildcard chrome-extension origin regex. "
        "Set ALLOWED_ORIGIN_REGEX to your specific published extension ID."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "YouTube Music Queue Saver Enterprise API",
        "version": "1.1.0",
    }


@app.get("/health")
@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    # Verify DB connectivity
    try:
        db.execute(models.User.__table__.select().limit(1))
        db_status = "connected"
    except Exception as e:
        logger.error("Health check DB connection failed: %s", e)
        db_status = "degraded"

    return {"status": "healthy", "database": db_status}


@app.post("/api/auth/register", response_model=schemas.TokenResponseSchema)
def register_user(payload: schemas.OAuthLoginSchema, db: Session = Depends(get_db)):
    """
    Registers or updates a user's stored OAuth credentials and issues a session token.
    Identity (google_id, email) is derived from verified Google credentials.
    """
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
def test_login(db: Session = Depends(get_db)):
    """
    Issues a verified session token for local testing without requiring external Google OAuth credentials.

    SECURITY: this route performs NO real authentication - it must never be
    reachable in production, since it's otherwise a one-request account
    takeover of the local_dev_user account. It now 404s (rather than 403,
    so its existence isn't even revealed) whenever APP_ENV=production.
    """
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
    """
    Saves a queue snapshot owned by the authenticated user.
    """
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
    """
    Retrieves the authenticated user's own snapshots for the specified category.
    """
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
    """
    Deletes a snapshot, but only if it belongs to the authenticated user.
    """
    snapshot = db.query(models.PlaylistSnapshot).filter(models.PlaylistSnapshot.id == snapshot_id).first()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    if snapshot.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this snapshot")

    db.delete(snapshot)
    db.commit()


@app.post("/api/restore/{snapshot_id}")
def restore_snapshot(
    snapshot_id: int,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    """
    Creates a real YouTube Music playlist from a saved snapshot in the authenticated
    user's personal account, using their decrypted Google OAuth credentials.
    """
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
