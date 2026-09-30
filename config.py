"""
Central configuration and feature flags.

Every environment-dependent knob lives here so that (a) the behaviour of the
service can be reasoned about in one place, and (b) anything risky can be
turned off with a single, documented environment variable without a code
change and without a redeploy of the extension.

Hard rule for this file: the DEFAULT value of every flag must reproduce the
behaviour that the currently-published browser extension depends on. Risky
optimisations therefore default to OFF.
"""

import os

# --- Deployment mode ---------------------------------------------------------
# IS_PRODUCTION drives every fail-closed behaviour (required secrets, no test
# login route, no Swagger UI, no OpenAPI schema).
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
IS_STAGING = APP_ENV == "staging"


def _flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on", "enabled")


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(value, minimum)


def _float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return max(value, minimum)


def _str_list(name: str) -> list:
    return [item.strip() for item in (os.getenv(name) or "").split(",") if item.strip()]


# --- Request hardening -------------------------------------------------------
# Body size cap applied to every mutating request, regardless of Content-Type.
MAX_REQUEST_BODY_BYTES = _int("MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024)
# Hard cap on `tracks` accepted in a single snapshot create. The published
# extension never sends anywhere near this many; the cap exists so a single
# request can never be used to force a 50-unit-per-track write storm.
MAX_TRACKS_PER_SNAPSHOT = _int("MAX_TRACKS_PER_SNAPSHOT", 1000)
# Validated Host header allowlist. Empty list disables the check (default, which
# preserves the behaviour behind Render/Heroku/Railway/etc. where the public
# hostname is not known ahead of time).
ALLOWED_HOSTS = _str_list("ALLOWED_HOSTS")
# Accepted Content-Type for JSON bodies.
ALLOWED_JSON_CONTENT_TYPES = ("application/json", "application/vnd.api+json")
# Maximum bytes accepted for the Google token payload at /api/auth/register.
MAX_TOKEN_PAYLOAD_BYTES = _int("MAX_TOKEN_PAYLOAD_BYTES", 16 * 1024)

# --- Security response headers ------------------------------------------------
ENABLE_HSTS = _flag("ENABLE_HSTS", default=IS_PRODUCTION)
ENABLE_CSP = _flag("ENABLE_CSP", default=IS_PRODUCTION)
HSTS_MAX_AGE = _int("HSTS_MAX_AGE", 31536000)
# The API serves JSON only and is never embedded in a frame.
CSP_VALUE = os.getenv(
    "CSP_VALUE",
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
)

# --- Rate limiting ------------------------------------------------------------
# Per-IP (existing) plus per-user (new) limits. The published extension performs
# at most one restore per user action, so these caps sit far above real usage.
RATE_LIMIT_REGISTER_PER_MIN = _int("RATE_LIMIT_REGISTER_PER_MIN", 5)
RATE_LIMIT_TEST_LOGIN_PER_MIN = _int("RATE_LIMIT_TEST_LOGIN_PER_MIN", 10)
RATE_LIMIT_LOGOUT_PER_MIN = _int("RATE_LIMIT_LOGOUT_PER_MIN", 30)
RATE_LIMIT_RESTORE_PER_MIN = _int("RATE_LIMIT_RESTORE_PER_MIN", 10)
RATE_LOGIN_PER_HOUR = _int("RATE_LOGIN_PER_HOUR", 60)
RATE_RESTORE_PER_HOUR = _int("RATE_RESTORE_PER_HOUR", 120)
RATE_DELETE_ACCOUNT_PER_MIN = _int("RATE_DELETE_ACCOUNT_PER_MIN", 3)

# --- YouTube API unit costs ---------------------------------------------------
# https://developers.google.com/youtube/v3/determine_quota_cost
# NOTE: a 304 Not Modified response still costs the request's units, which is
# why nothing in this service relies on ETags for quota savings.
YOUTUBE_UNIT_COST = {
    "search.list": 100,
    "videos.list": 1,
    "playlists.list": 1,
    "playlists.insert": 50,
    "playlistItems.list": 1,
    "playlistItems.insert": 50,
    "videos.insert": 1600,
    "videos.rate": 50,
}
DEFAULT_DAILY_QUOTA = _int("YOUTUBE_DAILY_QUOTA", 10_000)

# --- Quota budgets and circuit breaker ---------------------------------------
# Hard ceiling on estimated units we allow ourselves to spend per Pacific day.
# Kept below DEFAULT_DAILY_QUOTA so that overshoot caused by in-flight requests
# cannot push the project past Google's limit.
QUOTA_GLOBAL_CAP = _int("YTM_QUOTA_GLOBAL_CAP", int(DEFAULT_DAILY_QUOTA * 0.95))
QUOTA_PER_USER_CAP = _int("YTM_QUOTA_USER_CAP", 5000)
# Percentage thresholds that emit an audit warning.
QUOTA_ALERT_WARN_PCT = _int("YTM_QUOTA_ALERT_WARN_PCT", 70)
QUOTA_ALERT_CRIT_PCT = _int("YTM_QUOTA_ALERT_CRIT_PCT", 90)
# When a restore is refused because a budget is exhausted we still return the
# same HTTP 502 + {"detail": ...} body the extension already handles.
QUOTA_EXCEEDED_HTTP_STATUS = _int("QUOTA_EXCEEDED_HTTP_STATUS", 502)

# --- YouTube call behaviour ---------------------------------------------------
# Seconds a cached playlist ID is trusted before we spend 1 unit re-verifying it
# with playlists.list. 0 disables the TTL (verify on every restore).
PLAYLIST_VERIFY_TTL_SECONDS = _int("YTM_PLAYLIST_VERIFY_TTL_SECONDS", 900)
# Retry policy. 429/403 quotaExceeded is NEVER retried: a failed retry still
# burns quota. Only 5xx and the transient 409 ABORTED are retried.
YTM_MAX_RETRIES = _int("YTM_MAX_RETRIES", 2)
YTM_RETRY_BASE_SECONDS = _float("YTM_RETRY_BASE_SECONDS", 0.5)
YTM_RETRY_MAX_SECONDS = _float("YTM_RETRY_MAX_SECONDS", 8.0)
YTM_HTTP_TIMEOUT_SECONDS = _int("YTM_HTTP_TIMEOUT_SECONDS", 10)
# How many pages of playlistItems.list to mirror before giving up. Each page is
# 1 unit, so this bounds the sync cost at PLAYLIST_SYNC_MAX_PAGES units.
PLAYLIST_SYNC_MAX_PAGES = _int("YTM_PLAYLIST_SYNC_MAX_PAGES", 40)
# Playlist creation is 50 units. This many creates per user per Pacific day stops
# a delete/recreate loop from draining the shared project quota.
MAX_PLAYLIST_CREATES_PER_USER_PER_DAY = _int("YTM_MAX_PLAYLIST_CREATES_PER_USER_PER_DAY", 20)

# --- Feature flags (risky optimisations default to OFF) -----------------------
# Collapse repeated video IDs inside a single snapshot into one playlist insert.
# Off-by-default is deliberately conservative, but note the shipped Phase 1
# already deduplicates against previously inserted items, so turning this on only
# changes behaviour for a queue that literally lists the same song twice.
FLAG_DEDUPE_WITHIN_SNAPSHOT = _flag("YTM_DEDUPE_WITHIN_SNAPSHOT", default=False)
# Batch-validate candidate video IDs with videos.list (1 unit / 50 IDs) before
# spending 50 units per insert on IDs that may be deleted or private.
FLAG_VALIDATE_VIDEO_IDS = _flag("YTM_VALIDATE_VIDEO_IDS", default=False)
# Allow the ytmusicapi fallback path. It creates a fresh playlist on every run
# and bypasses quota accounting, so it is disabled in production by default.
FLAG_ALLOW_YTMUSICAPI_FALLBACK = _flag(
    "YTM_ALLOW_YTMUSICAPI_FALLBACK", default=not IS_PRODUCTION
)
# Persist restores that were refused because a budget was exhausted so they can
# be replayed after the Pacific midnight reset. OFF by default: the live
# extension is synchronous, so replaying later would create a playlist the user
# was already told had failed.
FLAG_DURABLE_REPLAY_QUEUE = _flag("YTM_DURABLE_REPLAY_QUEUE", default=False)
# Persist the refreshed access token after a single-flight refresh. Off means a
# refresh is only ever used for the in-flight request.
FLAG_PERSIST_REFRESHED_TOKEN = _flag("AUTH_PERSIST_REFRESHED_TOKEN", default=False)

# --- Enforced Origin / CSRF ---------------------------------------------------
# Log-only by default because the published extension cannot send new headers.
# Turn on only after confirming the exact extension ID is in ALLOWED_ORIGINS.
FLAG_ENFORCE_ORIGIN = _flag("ENFORCE_ORIGIN", default=False)

# --- OAuth / token ------------------------------------------------------------
GOOGLE_CLIENT_ID = os.getenv("YTM_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
# Only used when YTM_CLIENT_ID is unset.
GOOGLE_YOUTUBE_SCOPES = _str_list("GOOGLE_YOUTUBE_SCOPES") or [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
]
# Fields the backend is willing to persist from token_data. Anything else is
# dropped before it reaches the database.
ALLOWED_TOKEN_FIELDS = (
    "access_token",
    "refresh_token",
    "scope",
    "token_type",
    "expires_at",
    "expires_in",
    "expiry_date",
    "id_token",
)

# --- Session JWTs -------------------------------------------------------------
JWT_ALGORITHM = "RS256"
JWT_ISSUER = "saveQueue"
JWT_AUDIENCE = "saveQueue-client"
JWT_EXPIRE_MINUTES = _int("JWT_EXPIRE_MINUTES", 10080)  # 7 days
# Idle timeout: revoked JTIs older than this are pruned automatically.
REVOKED_TOKEN_RETENTION_DAYS = _int("REVOKED_TOKEN_RETENTION_DAYS", 30)

# --- CORS ---------------------------------------------------------------------
ALLOWED_ORIGINS = _str_list("ALLOWED_ORIGINS")
ALLOWED_ORIGIN_REGEX = os.getenv("ALLOWED_ORIGIN_REGEX")

# --- Observability ------------------------------------------------------------
AUDIT_LOG_ENABLED = _flag("AUDIT_LOG_ENABLED", default=True)
# Emit structured audit events instead of plain log lines.
LOG_FORMAT_JSON = _flag("LOG_FORMAT_JSON", default=False)


def ytm_unit_cost(method: str) -> int:
    """Units consumed by a YouTube Data API call, or 1 as a safe default."""
    return YOUTUBE_UNIT_COST.get(method, 1)
