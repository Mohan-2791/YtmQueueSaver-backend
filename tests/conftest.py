"""
Shared test fixtures.

Tests run against a throwaway SQLite database and stub out every outbound
network call, so nothing here talks to Google or consumes quota.
"""

import os
import sys
import tempfile

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

_TMP_DB = os.path.join(tempfile.gettempdir(), "ytm_saver_test.db")
if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

os.environ.setdefault("APP_ENV", "development")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ.setdefault("KMS_MASTER_KEY", "")
os.environ.setdefault("FERNET_KEY", "")
os.environ.setdefault("ALLOWED_ORIGINS", "chrome-extension://iegedaeoaampnaagmbfdefigjecepigo")
os.environ.setdefault("AUDIT_LOG_ENABLED", "false")
# The suite mints one session per test; the production caps would otherwise
# make the suite order-dependent. Behaviour under the real caps is covered by
# TestRateLimit below.
os.environ["RATE_LIMIT_TEST_LOGIN_PER_MIN"] = "10000"
os.environ["RATE_LIMIT_LOGOUT_PER_MIN"] = "10000"
os.environ["RATE_LIMIT_RESTORE_PER_MIN"] = "10000"
os.environ["RATE_RESTORE_PER_HOUR"] = "10000"
os.environ["RATE_LIMIT_REGISTER_PER_MIN"] = "10000"
os.environ["RATE_DELETE_ACCOUNT_PER_MIN"] = "10000"

import pytest  # noqa: E402

import auth as auth_module  # noqa: E402


@pytest.fixture(scope="session")
def app_module():
    import main

    return main


@pytest.fixture(scope="session", autouse=True)
def _schema(app_module):
    """
    Create the test schema up front.

    This must not depend on the HTTP client fixture: the quota/crypto unit tests
    never build one, and relying on that side effect made them fail whenever
    they ran alone or in a different order.
    """
    import models
    from database import engine

    models.Base.metadata.create_all(engine)


@pytest.fixture(scope="session")
def client(app_module):
    from fastapi.testclient import TestClient

    with TestClient(app_module.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def db_factory(app_module):
    from database import SessionLocal

    return SessionLocal


@pytest.fixture
def user(db_factory):
    from auth import encrypt_tokens
    import models

    session = db_factory()
    try:
        record = models.User(
            google_id=f"test-google-{os.urandom(6).hex()}",
            email="test@example.com",
            encrypted_token_json="",
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        record.encrypted_token_json = encrypt_tokens({"access_token": "test-access-token"}, record.id)
        session.commit()
        yield record
    finally:
        session.close()


@pytest.fixture
def bearer(client):
    """Creates a user via the dev-only test-login route and returns its token."""
    response = client.post("/api/auth/test-login")
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
def account(db_factory):
    """
    A brand-new account with a session token, for a single test.

    Every test needs its own user: the playlist cache, the local item mirror and
    the daily quota ledger are all keyed by user, so sharing one account across
    the suite would make the tests order-dependent. Teardown has to remove the
    user's derived rows too, because SQLite hands the freed rowid to the next
    fixture and a leftover UserPlaylist would look like a valid cache hit.
    """
    import models

    session = db_factory()
    try:
        record = models.User(
            google_id=f"acct-{os.urandom(8).hex()}",
            email=f"{os.urandom(4).hex()}@example.com",
            encrypted_token_json="",
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        yield record
    finally:
        user_id = record.id
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
        session.query(models.PlaylistSnapshot).filter_by(user_id=user_id).delete(
            synchronize_session=False
        )
        session.query(models.User).filter_by(id=user_id).delete(synchronize_session=False)
        session.commit()
        session.close()


@pytest.fixture
def fresh_bearer(account):
    return auth_module.create_access_token(account.id)


@pytest.fixture
def fresh_headers(fresh_bearer):
    return {"Authorization": f"Bearer {fresh_bearer}"}


@pytest.fixture
def auth_headers(bearer):
    return {"Authorization": f"Bearer {bearer}"}
