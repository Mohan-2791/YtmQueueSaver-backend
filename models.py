import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    # NOTE: original code had `primary_class=True`, which is not a valid
    # SQLAlchemy Column kwarg and would raise a TypeError at import time,
    # crashing the app before it ever starts.
    id = Column(Integer, primary_key=True, index=True)
    google_id = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=True)
    encrypted_token_json = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # --- additive columns (nullable / defaulted, no data backfill required) ---
    # Set when Google tells us the stored credential is dead (invalid_grant,
    # 401 from the Data API, token revoked by the user). The route layer already
    # returns the existing "please sign in" 400 body, so this is purely an
    # observable flag for alerting and for the settings UI to pick up later.
    needs_reconnect = Column(Boolean, nullable=False, default=False, server_default="false")
    last_seen_at = Column(DateTime, nullable=True)

    snapshots = relationship("PlaylistSnapshot", back_populates="owner", cascade="all, delete-orphan")
    user_playlists = relationship(
        "UserPlaylist", back_populates="owner", cascade="all, delete-orphan"
    )


class PlaylistSnapshot(Base):
    __tablename__ = "playlist_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False, index=True)  # 'SESSION_WIPE' or 'ARCHIVE_HISTORY'
    playback_mode = Column(String(20), default="SONG")          # 'SONG' or 'VIDEO'
    tracks = Column(JSON, nullable=False)                        # List of {videoId, title, artist}
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="snapshots")

    __table_args__ = (
        # The only read pattern is "all snapshots for (user, category), newest
        # first"; without this the filter+sort degrades to a full scan once a
        # user has an archive history.
        Index("ix_snapshots_user_category_created", "user_id", "category", "created_at"),
    )


class UserPlaylist(Base):
    """Maps a (user_id, category) to an existing YouTube Playlist ID."""
    __tablename__ = "user_playlists"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    youtube_playlist_id = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # --- additive columns ---
    # When we last spent 1 unit confirming this playlist still exists. Lets the
    # restore path skip playlists.list entirely inside the TTL window.
    verified_at = Column(DateTime, nullable=True)
    # Title used at creation time, kept so a recreated playlist can preserve
    # the user's naming without an extra playlists.list round trip.
    title = Column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint('user_id', 'category', name='uq_user_category'),
    )

    owner = relationship("User", back_populates="user_playlists")


class PlaylistItemsCache(Base):
    """Local mirror of videoIds known to be in a specific YouTube Playlist."""
    __tablename__ = "playlist_items_cache"

    id = Column(Integer, primary_key=True, index=True)
    youtube_playlist_id = Column(String(255), nullable=False, index=True)
    video_id = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('youtube_playlist_id', 'video_id', name='uq_playlist_video'),
        # Covers "is this video already mirrored for this playlist?" which runs
        # once per candidate track on every restore.
        Index("ix_playlist_items_cache_lookup", "youtube_playlist_id", "video_id"),
    )


class QuotaUsage(Base):
    """Tracks estimated YouTube API quota units consumed."""
    __tablename__ = "quota_usage"

    id = Column(Integer, primary_key=True, index=True)
    date_str = Column(String(10), nullable=False, index=True)  # YYYY-MM-DD in PT
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    units_used = Column(Integer, default=0, nullable=False)

    # --- additive column ---
    # Abuse control: bounds how many playlists a single account can create per
    # Pacific day, each of which costs 50 units of the shared project quota.
    playlists_created = Column(Integer, nullable=False, default=0, server_default="0")

    __table_args__ = (
        UniqueConstraint('date_str', 'user_id', name='uq_date_user'),
        # The global cap check sums units_used for a day on every restore.
        Index("ix_quota_usage_date_units", "date_str", "units_used"),
    )


class RevokedToken(Base):
    """Tracks revoked JWT session tokens to implement server-side logout."""
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
