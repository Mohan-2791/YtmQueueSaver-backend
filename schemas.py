import datetime
import re
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator

ALLOWED_CATEGORIES = ("SESSION_WIPE", "ARCHIVE_HISTORY")
ALLOWED_PLAYBACK_MODES = ("SONG", "VIDEO")


class TrackSchema(BaseModel):
    videoId: str = Field(..., min_length=1, max_length=64, example="dQw4w9WgXcQ")
    title: str = Field(..., min_length=1, max_length=500, example="Never Gonna Give You Up")
    artist: Optional[str] = Field(default="Unknown Artist", max_length=500)
    duration: Optional[str] = Field(default=None, max_length=50)
    thumbnail: Optional[str] = Field(default=None, max_length=1000)
    isPlaying: Optional[bool] = Field(default=None)

    @field_validator("videoId")
    @classmethod
    def videoId_must_be_sane(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", v):
            raise ValueError("videoId contains unexpected characters")
        return v


class SnapshotCreateSchema(BaseModel):
    # user_id intentionally removed: the owner is derived from the
    # authenticated session, never taken from the request body.
    title: str = Field(..., min_length=1, max_length=255, example="Auto-Saved Queue")
    category: Literal[ALLOWED_CATEGORIES] = Field(..., example="SESSION_WIPE")
    playback_mode: Literal[ALLOWED_PLAYBACK_MODES] = Field(default="SONG")
    tracks: List[TrackSchema] = Field(..., max_length=10000)


class SnapshotResponseSchema(BaseModel):
    id: int
    user_id: int
    title: str
    category: str
    playback_mode: str
    tracks: List[TrackSchema]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class OAuthLoginSchema(BaseModel):
    # A real Google credential -- either an ID token (JWT) or an OAuth access
    # token (e.g. from chrome.identity.getAuthToken()) -- verified
    # server-side in auth.verify_google_token. google_id/email are NEVER
    # trusted from the client directly.
    id_token: str = Field(..., min_length=1)
    # The ytmusicapi OAuth token payload (access_token/refresh_token/etc.) to
    # store encrypted, used later to act on the user's YouTube Music account.
    token_data: dict


class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int