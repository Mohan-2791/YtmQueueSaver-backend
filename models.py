import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
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

    snapshots = relationship("PlaylistSnapshot", back_populates="owner", cascade="all, delete-orphan")


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
