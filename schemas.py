import datetime
import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

import config

ALLOWED_CATEGORIES = ("SESSION_WIPE", "ARCHIVE_HISTORY")
ALLOWED_PLAYBACK_MODES = ("SONG", "VIDEO")

VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
PLAYLIST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{2,128}$")


class StrictModel(BaseModel):
    """
    Base model for everything that crosses the network.

    `extra="forbid"` is the important part: without it a client can smuggle
    arbitrary keys into a payload, and the first place they get spread into a DB
    model or an outbound API call is a mass-assignment bug. It is a no-op for
    the published extension, which only ever sends the documented fields.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class TrackSchema(StrictModel):
    videoId: str = Field(..., min_length=11, max_length=11, example="dQw4w9WgXcQ")
    title: str = Field(..., min_length=1, max_length=500, example="Never Gonna Give You Up")
    artist: Optional[str] = Field(default="Unknown Artist", max_length=500)
    duration: Optional[str] = Field(default=None, max_length=50)
    thumbnail: Optional[str] = Field(default=None, max_length=1000)
    isPlaying: Optional[bool] = Field(default=None)

    @field_validator("videoId")
    @classmethod
    def videoId_must_be_sane(cls, v: str) -> str:
        if not VIDEO_ID_RE.fullmatch(v):
            raise ValueError("videoId contains unexpected characters or invalid length")
        return v


class SnapshotCreateSchema(StrictModel):
    title: str = Field(..., min_length=1, max_length=255, example="Auto-Saved Queue")
    category: Literal[ALLOWED_CATEGORIES] = Field(..., example="SESSION_WIPE")
    playback_mode: Literal[ALLOWED_PLAYBACK_MODES] = Field(default="SONG")
    tracks: List[TrackSchema] = Field(..., max_length=config.MAX_TRACKS_PER_SNAPSHOT)


class SnapshotResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    title: str
    category: str
    playback_mode: str
    tracks: List[TrackSchema]
    created_at: datetime.datetime


class OAuthTokenData(BaseModel):
    """
    The subset of Google token material we are willing to persist.

    The extension posts `{ "access_token": "<token>" }`. Anything else the
    client sends is dropped rather than stored verbatim.
    """

    model_config = ConfigDict(extra="ignore")

    access_token: Optional[str] = Field(default=None, max_length=8192)
    refresh_token: Optional[str] = Field(default=None, max_length=8192)
    scope: Optional[str] = Field(default=None, max_length=4096)
    token_type: Optional[str] = Field(default=None, max_length=64)
    expires_at: Optional[Any] = Field(default=None)
    expires_in: Optional[Any] = Field(default=None)
    expiry_date: Optional[Any] = Field(default=None)
    id_token: Optional[str] = Field(default=None, max_length=8192)

    def to_storable(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for field in config.ALLOWED_TOKEN_FIELDS:
            value = getattr(self, field, None)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                result[field] = text[:4096]
        return result


class OAuthLoginSchema(StrictModel):
    id_token: str = Field(..., min_length=1, max_length=8192)
    # `token_data` is a free-form object in the wire contract, but it is parsed
    # into OAuthTokenData so only whitelisted, length-bounded keys survive.
    token_data: OAuthTokenData = Field(default_factory=OAuthTokenData)


class TokenResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    token_type: str = "bearer"
    user_id: int
