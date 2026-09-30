import datetime
import logging
import os
import threading
import time
from typing import Optional

import jwt
import requests
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from sqlalchemy.orm import Session

import audit
import config
import crypto
from database import get_db
import models

logger = logging.getLogger("ytm_saver.auth")

APP_ENV = config.APP_ENV
IS_PRODUCTION = config.IS_PRODUCTION

# One pooled session for all outbound Google identity calls: keeps TLS
# connections alive across requests instead of paying a new handshake every
# time, and is the single place outbound egress is scoped.
_google_http = requests.Session()
_google_http.headers.update({"User-Agent": "ytm-queue-saver/1.1"})

bearer_scheme = HTTPBearer(auto_error=False)


# --- App-issued session JWT (asymmetric, RS256) ------------------------------
def _load_jwt_keys():
    private_key = os.getenv("JWT_PRIVATE_KEY")
    public_key = os.getenv("JWT_PUBLIC_KEY")
    if private_key and public_key:
        # Support literal "\n" escapes, which is how these usually end up in a
        # PaaS dashboard's single-line environment variable editor.
        private_key = private_key.replace("\\n", "\n")
        public_key = public_key.replace("\\n", "\n")
        return private_key, public_key
    if IS_PRODUCTION:
        raise RuntimeError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required in production for RS256 JWTs.")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    logger.warning("JWT keys not set - generated ephemeral RSA keypair for dev.")
    return private_pem, public_pem


JWT_PRIVATE_KEY, JWT_PUBLIC_KEY = _load_jwt_keys()


# --- Google credential verification ------------------------------------------
GOOGLE_CLIENT_ID = config.GOOGLE_CLIENT_ID
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

    `verify_oauth2_token` checks the RS256 signature against Google's published
    certs, the `aud` claim, the `iss` claim and `exp`. We additionally pin `iss`
    explicitly because a misconfigured or attacker-supplied issuer would
    otherwise be the library's problem.
    """
    if not GOOGLE_CLIENT_ID:
        return None

    try:
        payload = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_CLIENT_ID
        )
    except ValueError as exc:
        logger.info("Google ID token verification failed: %s", type(exc).__name__)
        return None

    if payload.get("aud") != GOOGLE_CLIENT_ID:
        return None
    if payload.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        return None
    if not payload.get("sub"):
        return None

    # `nonce` is only meaningful if this backend generated one; the published
    # extension performs the ID-token exchange through chrome.identity, so we
    # observe but do not verify it. Flagged as [NEEDS FRONTEND] in HARDENING.md.
    if "nonce" in payload:
        logger.debug("Google ID token carries a nonce (not verified: flow is extension-owned)")
    return payload


def verify_google_access_token(access_token_str: str) -> Optional[dict]:
    """
    Verify a Google OAuth access token (from chrome.identity in the extension).

    Rejects the token outright unless it was minted for *this* OAuth client, and
    identifies the account by Google's stable `sub` - never by email, which a
    user can change and which can be reassigned.
    """
    if not GOOGLE_CLIENT_ID:
        logger.warning(
            "Rejecting access token verification attempt: GOOGLE_CLIENT_ID is not configured."
        )
        return None

    try:
        info_resp = _google_http.get(
            config.GOOGLE_TOKENINFO_URL,
            params={"access_token": access_token_str},
            timeout=5,
        )
    except requests.RequestException:
        return None

    if info_resp.status_code != 200:
        return None

    try:
        info = info_resp.json()
    except ValueError:
        return None

    if GOOGLE_CLIENT_ID not in (info.get("aud"), info.get("azp")):
        logger.warning(
            "Rejecting access token: client ID did not match the configured client"
        )
        return None

    # Granular consent: trust the granted scopes, never assume them.
    granted_scope = info.get("scope") or ""
    if granted_scope and not any(scope in granted_scope for scope in config.GOOGLE_YOUTUBE_SCOPES):
        logger.warning(
            "Rejecting access token: granted scopes do not include YouTube write access"
        )
        return None

    try:
        userinfo_resp = _google_http.get(
            config.GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token_str}"},
            timeout=5,
        )
    except requests.RequestException:
        return None

    if userinfo_resp.status_code != 200:
        return None

    try:
        userinfo = userinfo_resp.json()
    except ValueError:
        return None

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

    Returns a dict that ALWAYS contains a non-empty `sub`. Identifies the
    account by Google's `sub` only.
    """
    if not isinstance(token_str, str) or not token_str.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google credential"
        )
    token_str = token_str.strip()
    # A Google access token or an ID token; both are bounded JWT-ish strings.
    if len(token_str) > 8192:
        audit.security_event("auth.credential_too_large", outcome="denied", size=len(token_str))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google credential"
        )

    payload = verify_google_id_token(token_str)
    if payload is not None:
        return {"sub": payload["sub"], "email": payload.get("email")}

    payload = verify_google_access_token(token_str)
    if payload is not None:
        return payload

    audit.security_event("auth.credential_rejected", outcome="denied")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google credential")


# --- Stored-token helpers -----------------------------------------------------
def encrypt_tokens(token_dict: dict, user_id: int) -> str:
    """Seal an OAuth token dictionary for storage (AES-256-GCM envelope)."""
    return crypto.encrypt_tokens(token_dict, user_id)


def decrypt_tokens(encrypted_str: str, user_id: int) -> dict:
    """Unseal a stored token dictionary. Returns {} when unreadable."""
    return crypto.decrypt_tokens(encrypted_str, user_id)


def needs_reencrypt(encrypted_str: str) -> bool:
    return crypto.needs_reencrypt(encrypted_str)


# --- Single-flight access-token refresh --------------------------------------
_refresh_locks: dict = {}
_refresh_locks_guard = threading.Lock()


def _user_lock(user_id: int) -> threading.Lock:
    with _refresh_locks_guard:
        lock = _refresh_locks.get(user_id)
        if lock is None:
            lock = threading.Lock()
            _refresh_locks[user_id] = lock
        return lock


def _token_expired(token_data: dict, leeway_seconds: int = 120) -> bool:
    """Best-effort expiry check. Unknown expiry is treated as NOT expired."""
    expires_at = token_data.get("expires_at") or token_data.get("expiry_date")
    if expires_at:
        try:
            value = float(expires_at)
        except (TypeError, ValueError):
            return False
        # chrome.identity-style clients send epoch seconds; ytmusicapi sends a
        # local-time datetime string. Only the numeric form is interpreted.
        if value > 1_000_000_000:
            return value <= (time.time() + leeway_seconds)
        return False
    expires_in = token_data.get("expires_in")
    if expires_in and token_data.get("acquired_at"):
        try:
            return (float(token_data["acquired_at"]) + float(expires_in)) <= time.time() + leeway_seconds
        except (TypeError, ValueError):
            return False
    return False


def refresh_access_token(token_data: dict, user_id: int) -> Optional[dict]:
    """
    Exchange a stored refresh token for a fresh access token.

    Returns the updated token dict, or None when a refresh is not possible.
    Serialised per user by a lock so N concurrent restores trigger exactly one
    token refresh rather than N racing `invalid_grant` errors (which would also
    invalidate the shared refresh token).
    """
    refresh_token = token_data.get("refresh_token")
    if not refresh_token or not GOOGLE_CLIENT_ID:
        return None

    lock = _user_lock(user_id)
    if not lock.acquire(blocking=False):
        # Someone else is already refreshing for this user. Wait for them
        # rather than starting a competing exchange.
        if lock.acquire(timeout=10):
            lock.release()
            return None  # caller should re-read the stored token
        return None
    try:
        body = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": GOOGLE_CLIENT_ID,
        }
        client_secret = os.getenv("YTM_CLIENT_SECRET")
        if client_secret:
            body["client_secret"] = client_secret
        try:
            resp = _google_http.post(config.GOOGLE_TOKEN_URL, data=body, timeout=10)
        except requests.RequestException as exc:
            logger.warning("Token refresh request failed for user %s: %s", user_id, exc)
            return None

        if resp.status_code != 200:
            try:
                err = resp.json().get("error", "unknown")
            except ValueError:
                err = "unknown"
            audit.security_event(
                "auth.token_refresh_failed", user_id=user_id, outcome="denied", error=err
            )
            return None

        try:
            payload = resp.json()
        except ValueError:
            return None

        updated = dict(token_data)
        if payload.get("access_token"):
            updated["access_token"] = payload["access_token"]
        if payload.get("refresh_token"):
            updated["refresh_token"] = payload["refresh_token"]
        if payload.get("scope"):
            updated["scope"] = payload["scope"]
        updated["expires_in"] = payload.get("expires_in", 3600)
        updated["expires_at"] = int(time.time()) + int(updated.get("expires_in") or 3600)
        updated["token_type"] = payload.get("token_type", "Bearer")
        return updated
    finally:
        try:
            lock.release()
        except RuntimeError:  # pragma: no cover
            pass


def revoke_google_token(token: str) -> bool:
    """Best-effort revocation at Google's revoke endpoint."""
    if not token:
        return False
    try:
        resp = _google_http.post(
            config.GOOGLE_REVOKE_URL,
            data={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5,
        )
        return resp.status_code in (200, 204)
    except requests.RequestException as exc:
        logger.warning("Google token revocation failed: %s", exc)
        return False


# --- Session tokens -----------------------------------------------------------
def create_access_token(user_id: int) -> str:
    """Issues a signed RS256 JWT session token for the user."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expire = now + datetime.timedelta(minutes=config.JWT_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": config.JWT_ISSUER,
        "aud": config.JWT_AUDIENCE,
        "jti": audit.new_nonce(),
    }
    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm=config.JWT_ALGORITHM)


def revoke_session(db: Session, user, reason: str = "logout") -> bool:
    """
    Server-side logout: blacklist the presented token's `jti` until it would
    have expired anyway. Additive route, no frontend change required.
    """
    jti = getattr(user, "current_jti", None)
    if not jti:
        return False
    exp = getattr(user, "current_exp", None)
    try:
        expires_at = datetime.datetime.utcfromtimestamp(int(exp))
    except (TypeError, ValueError, OverflowError, OSError):
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    db.add(models.RevokedToken(jti=jti, expires_at=expires_at))
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to revoke session for user %s", getattr(user, "id", "?"))
        return False
    audit.security_event(
        "auth.logout", user_id=getattr(user, "id", None), outcome="ok", reason=reason
    )
    return True


def prune_revoked_tokens(db: Session) -> int:
    """Drop blacklist entries for tokens that expired more than N days ago."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(
        days=config.REVOKED_TOKEN_RETENTION_DAYS
    )
    deleted = db.query(models.RevokedToken).filter(models.RevokedToken.expires_at < cutoff).delete()
    if deleted:
        db.commit()
        logger.info("Pruned %s expired revoked-token entries", deleted)
    return int(deleted or 0)


def mark_needs_reconnect(db: Session, user, reason: str) -> None:
    """
    Flag the account as needing a fresh Google sign-in and drop the dead token.

    `needs_reconnect` is additive and invisible to the published extension; the
    caller still returns the existing "please sign in" 400 body.
    """
    try:
        user.encrypted_token_json = ""
        if hasattr(models.User, "needs_reconnect"):
            user.needs_reconnect = True
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to mark user %s as needing reconnect", getattr(user, "id", "?"))
    audit.security_event(
        "auth.reconnect_required",
        user_id=getattr(user, "id", None),
        outcome="denied",
        reason=reason,
    )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Derives and verifies the authenticated user from the Bearer JWT token.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # `algorithms=[...]` pins the accepted algorithm, which is what rejects
        # `alg: none` and any HMAC downgrade attempt on an RS256 service.
        payload = jwt.decode(
            credentials.credentials,
            JWT_PUBLIC_KEY,
            algorithms=[config.JWT_ALGORITHM],
            audience=config.JWT_AUDIENCE,
            issuer=config.JWT_ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
        user_id = int(payload.get("sub"))
        jti = payload.get("jti")
    except (jwt.PyJWTError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if jti:
        is_revoked = db.query(models.RevokedToken).filter(models.RevokedToken.jti == jti).first()
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Carry the validated claims so a route can revoke this exact token.
    user.current_jti = jti
    user.current_exp = payload.get("exp")
    return user
