import os
import json
import base64
import secrets
import datetime
import logging
from typing import Optional

import jwt
import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.fernet import Fernet
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from sqlalchemy.orm import Session

from database import get_db
import models

logger = logging.getLogger("ytm_saver.auth")

# --- Environment mode --------------------------------------------------------
# Controls whether we allow convenience fallbacks (ephemeral dev secrets,
# the /api/auth/test-login route). Set APP_ENV=production in any real
# deployment. Defaults to "development" so local setup keeps working
# out of the box with zero extra config.
APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

# --- App-issued session JWT --------------------------------------------------
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "10080"))  # 7 days default

bearer_scheme = HTTPBearer(auto_error=False)

# SECURITY: previously this fell back to a hardcoded string
# ("ytm-queue-saver-production-secret-change-me") baked into source control.
# Anyone who read the repo could forge a valid session JWT for any user ID.
# Now: production refuses to boot without an explicit secret, and local/dev
# gets a random secret generated fresh each process start (sessions just
# won't survive a restart, which is fine for dev and safe by default).
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    if IS_PRODUCTION:
        raise RuntimeError(
            "JWT_SECRET is not set. Refusing to start in production without an explicit, "
            "randomly generated secret. Set the JWT_SECRET environment variable "
            "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(64))\"`)."
        )
    JWT_SECRET = secrets.token_urlsafe(64)
    logger.warning(
        "JWT_SECRET not set - generated an ephemeral random secret for this dev process. "
        "Existing sessions will NOT survive a restart. Set JWT_SECRET explicitly for anything "
        "beyond local development."
    )

# --- Symmetric encryption for stored OAuth tokens --------------------------
# SECURITY: previously derived deterministically from JWT_SECRET, meaning a
# leak of one secret leaked both the session-signing key AND the key
# protecting every user's stored YouTube OAuth credentials. These must be
# independent secrets. Production now requires FERNET_KEY explicitly; dev
# gets a freshly generated random key each process start.
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError(
            "FERNET_KEY is not set. Refusing to start in production without an explicit, "
            "independently generated encryption key. Set the FERNET_KEY environment variable "
            "(e.g. `python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\"`)."
        )
    FERNET_KEY = Fernet.generate_key().decode()
    logger.warning(
        "FERNET_KEY not set - generated an ephemeral random key for this dev process. "
        "Any tokens encrypted now will be UNREADABLE after a restart. Set FERNET_KEY "
        "explicitly for anything beyond local development."
    )

cipher = Fernet(FERNET_KEY.encode())


def encrypt_tokens(token_dict: dict) -> str:
    """Encrypt OAuth token dictionary before storing in database."""
    raw_json = json.dumps(token_dict)
    return cipher.encrypt(raw_json.encode()).decode()


def decrypt_tokens(encrypted_str: str) -> dict:
    """Decrypt token string back into dictionary for YouTube Music operations."""
    decrypted_bytes = cipher.decrypt(encrypted_str.encode())
    return json.loads(decrypted_bytes.decode())


# --- Google Credential verification -------------------------------------------
# SECURITY: previously, if this was left unset (typo, forgotten env var, etc),
# GOOGLE_CLIENT_ID was "" — which is falsy, so the audience check inside
# verify_google_access_token was silently skipped entirely. That meant ANY
# valid Google access token, minted for ANY OAuth client (not just this app),
# would be accepted as a login. Same class of bug as the JWT_SECRET/FERNET_KEY
# fallback, just not caught the first time around. Production now refuses to
# boot without it, exactly like the two secrets above.
GOOGLE_CLIENT_ID = os.getenv("YTM_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID", "")
if not GOOGLE_CLIENT_ID:
    if IS_PRODUCTION:
        raise RuntimeError(
            "YTM_CLIENT_ID (or GOOGLE_CLIENT_ID) is not set. Refusing to start in production "
            "without it - without this, Google credential verification cannot check the "
            "token's audience, which would allow tokens minted for other OAuth clients to be "
            "accepted as valid logins."
        )
    logger.warning(
        "YTM_CLIENT_ID/GOOGLE_CLIENT_ID not set - Google login verification will reject all "
        "credentials in this dev process. Use POST /api/auth/test-login for local development, "
        "or set YTM_CLIENT_ID to test real Google sign-in."
    )


def verify_google_id_token(id_token_str: str) -> Optional[dict]:
    """
    Verify a Google-issued ID token (a signed JWT) and return its payload.
    """
    if not GOOGLE_CLIENT_ID:
        return None

    try:
        payload = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError:
        return None

    if payload.get("aud") != GOOGLE_CLIENT_ID:
        return None
    if payload.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        return None

    return payload


def verify_google_access_token(access_token_str: str) -> Optional[dict]:
    """
    Verify a Google OAuth access token (from chrome.identity in the extension)
    by querying Google's tokeninfo endpoint and userinfo endpoint.
    """
    # SECURITY: hard reject rather than silently skip the audience check when
    # GOOGLE_CLIENT_ID isn't configured. In production this branch is
    # unreachable (see fail-closed check above); in dev it means access-token
    # login is disabled until YTM_CLIENT_ID is set, rather than accepting any
    # Google account's token unconditionally.
    if not GOOGLE_CLIENT_ID:
        logger.warning(
            "Rejecting access token verification attempt: GOOGLE_CLIENT_ID is not configured."
        )
        return None

    try:
        info_resp = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"access_token": access_token_str},
            timeout=5,
        )
    except requests.RequestException:
        return None

    if info_resp.status_code != 200:
        return None

    info = info_resp.json()

    # SECURITY: previously this only logged a warning on a client-ID mismatch
    # and then continued anyway, meaning an access token minted for a totally
    # different OAuth client (not this app) would still be accepted as long
    # as it resolved to *some* valid Google account. We now hard-reject.
    if GOOGLE_CLIENT_ID not in (info.get("aud"), info.get("azp")):
        logger.warning(
            "Rejecting access token: client ID %s did not match configured client %s",
            info.get("aud") or info.get("azp"),
            GOOGLE_CLIENT_ID,
        )
        return None

    try:
        userinfo_resp = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token_str}"},
            timeout=5,
        )
    except requests.RequestException:
        return None

    if userinfo_resp.status_code != 200:
        return None

    userinfo = userinfo_resp.json()
    sub = userinfo.get("sub")
    if not sub:
        return None

    return {
        "sub": sub,
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "picture": userinfo.get("picture"),
    }


def verify_google_token(token_str: str) -> dict:
    """
    Verifies either an ID token or an OAuth access token from the Google login.
    """
    payload = verify_google_id_token(token_str)
    if payload is not None:
        return {"sub": payload["sub"], "email": payload.get("email")}

    payload = verify_google_access_token(token_str)
    if payload is not None:
        return payload

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google credential")


def create_access_token(user_id: int) -> str:
    """Issues a signed JWT session token for the user."""
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Derives and verifies the authenticated user from the Bearer JWT token.

    SECURITY: this previously fell back to a default "user 1" (creating it if
    missing) whenever no Authorization header was present at all, which made
    every "protected" endpoint reachable anonymously. There is no longer any
    unauthenticated fallback - a missing or invalid token is always a 401.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
    except (jwt.PyJWTError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user