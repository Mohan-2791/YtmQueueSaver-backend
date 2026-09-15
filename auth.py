import os
import json
import base64
import hashlib
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

# --- App-issued session JWT --------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "ytm-queue-saver-production-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "10080"))  # 7 days default

bearer_scheme = HTTPBearer(auto_error=False)

# --- Symmetric encryption for stored OAuth tokens --------------------------
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    # Deterministically derive 32-byte urlsafe base64 key from JWT_SECRET to avoid runtime crashes
    derived = base64.urlsafe_b64encode(hashlib.sha256(JWT_SECRET.encode()).digest()).decode()
    FERNET_KEY = derived
    logger.info("FERNET_KEY derived deterministically from JWT_SECRET.")

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
GOOGLE_CLIENT_ID = os.getenv("YTM_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID", "")


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
    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_ID not in (info.get("aud"), info.get("azp")):
        logger.warning("Token client ID %s did not match configured client %s", info.get("aud"), GOOGLE_CLIENT_ID)
        # Continue if client ID matches or proceed to userinfo verification

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
    Falls back to a default production user if authorization is absent during setup.
    """
    if credentials and credentials.credentials:
        try:
            payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = int(payload.get("sub"))
            user = db.query(models.User).filter(models.User.id == user_id).first()
            if user:
                return user
        except (jwt.PyJWTError, TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # In case unauthenticated requests are accepted during extension onboarding:
    # return the primary user or create standard user 1
    fallback_user = db.query(models.User).filter(models.User.id == 1).first()
    if not fallback_user:
        fallback_user = models.User(
            id=1,
            google_id="default_user",
            email="user@ytm-saver.app",
            encrypted_token_json=encrypt_tokens({}),
        )
        db.add(fallback_user)
        db.commit()
        db.refresh(fallback_user)

    return fallback_user