import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from urllib.parse import quote_plus

logger = logging.getLogger("ytm_saver.db")

# Computed locally (not imported from auth.py) to avoid a circular import:
# auth.py imports `get_db` from this module, so this module cannot import
# anything back from auth.py.
APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "saveQueueDB")

# Allow override via full DATABASE_URL if present, otherwise construct safely
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    if DB_PASSWORD:
        encoded_password = quote_plus(DB_PASSWORD)
        DATABASE_URL = f"postgresql://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # SECURITY: previously this silently fell back to a local SQLite file
        # in ANY environment, including production. On most PaaS platforms
        # the filesystem is ephemeral, so the app would look like it was
        # working - users could register and save data - right up until the
        # next redeploy or restart wiped it all. Production now refuses to
        # start instead of silently degrading to a throwaway database.
        if IS_PRODUCTION:
            raise RuntimeError(
                "No database configured for production. Set DATABASE_URL (preferred, e.g. "
                "the value your hosting platform's managed Postgres provides) or DB_PASSWORD "
                "plus DB_USER/DB_HOST/DB_PORT/DB_NAME. Refusing to silently fall back to "
                "SQLite in production."
            )
        DATABASE_URL = "sqlite:///./ytm_queue_saver.db"
        logger.warning("No Postgres credentials found. Defaulting to local SQLite: %s", DATABASE_URL)

# Some managed Postgres providers hand out postgres:// URLs; SQLAlchemy needs postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs = {"connect_args": {"check_same_thread": False}}
else:
    engine_kwargs = {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 1800,
    }

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency injection helper for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()