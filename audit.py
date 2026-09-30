"""
Structured audit logging with correlation IDs.

Rules:
* One correlation id per request (`X-Request-ID` if the caller supplied a sane
  one, otherwise generated). It is echoed back on the response so a support
  ticket can be traced to exact log lines.
* Log lines are JSON-ish single-line records. CR/LF and other control
  characters coming from user-controlled data (titles, emails, origins) are
  escaped so an attacker cannot forge log entries.
* Tokens, authorization headers and raw request bodies are never logged.
"""

import contextvars
import datetime
import json
import logging
import re
import secrets
import uuid
from typing import Any, Optional

import config

_logger = logging.getLogger("ytm_saver.audit")

_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# Never emitted, even if a caller passes them in the details dict.
_FORBIDDEN_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "encrypted_token_json",
        "password",
        "secret",
        "cookie",
    }
)


def _escape(value: Any) -> str:
    """Collapse CR/LF and control characters so one event stays one line."""
    text = value if isinstance(value, str) else str(value)
    return _CONTROL_CHARS.sub(lambda m: "\\x%02x" % ord(m.group()), text)


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def sanitize_request_id(candidate: Optional[str]) -> Optional[str]:
    """Accept a caller-provided request id only if it is boring and short."""
    if candidate and _SAFE_REQUEST_ID.match(candidate):
        return candidate
    return None


def set_correlation_id(value: Optional[str]) -> str:
    cid = sanitize_request_id(value) or new_correlation_id()
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    return _correlation_id.get() or "no-correlation-id"


def _scrub(details: Optional[dict]) -> dict:
    if not details:
        return {}
    clean = {}
    for key, value in details.items():
        if str(key).lower() in _FORBIDDEN_KEYS:
            clean[key] = "[redacted]"
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = _escape(value)
        elif isinstance(value, (list, tuple)):
            clean[key] = [_escape(v) for v in value[:50]]
        elif isinstance(value, dict):
            clean[key] = _scrub(value)
        else:
            clean[key] = _escape(value)
    return clean


def audit(event: str, *, user_id: Optional[int] = None, outcome: str = "ok",
          **details: Any) -> None:
    """
    Record a security-relevant event.

    `event` is a dotted name (`auth.login`, `restore.refused`, ...). `outcome`
    is one of ok / denied / error.
    """
    if not config.AUDIT_LOG_ENABLED:
        return
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "correlation_id": get_correlation_id(),
        "event": _escape(event),
        "outcome": _escape(outcome),
    }
    if user_id is not None:
        record["user_id"] = user_id
    scrubbed = _scrub(details)
    if scrubbed:
        record["details"] = scrubbed

    if config.LOG_FORMAT_JSON:
        _logger.info(json.dumps(record, separators=(",", ":"), default=str))
    else:
        flat = " ".join(f"{k}={v}" for k, v in record.items() if k != "ts")
        _logger.info("%s ts=%s", _escape(event), record["ts"])
        _logger.info("  %s", _escape(flat))


def security_event(event: str, *, user_id: Optional[int] = None, outcome: str = "denied",
                   **details: Any) -> None:
    """Same as `audit` but emitted at WARNING so it survives normal log levels."""
    if not config.AUDIT_LOG_ENABLED:
        return
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "correlation_id": get_correlation_id(),
        "event": _escape(event),
        "outcome": _escape(outcome),
    }
    if user_id is not None:
        record["user_id"] = user_id
    scrubbed = _scrub(details)
    if scrubbed:
        record["details"] = scrubbed
    flat = " ".join(f"{k}={v}" for k, v in record.items() if k != "ts")
    _logger.warning("SECURITY %s", _escape(flat))


def new_nonce() -> str:
    """URL-safe random value for state/nonce/idempotency keys."""
    return secrets.token_urlsafe(24)
