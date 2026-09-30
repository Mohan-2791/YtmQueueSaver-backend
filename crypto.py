"""
Envelope encryption for stored Google OAuth tokens.

Format (v3)
-----------
    v3:<key_id>:<wrapped_dek_b64>:<dek_nonce_b64>:<payload_nonce_b64>:<payload_ct_b64>

* A fresh 256-bit data key (DEK) is generated for **every** record.
* The payload (JSON token dict) is sealed with AES-256-GCM under the DEK using a
  unique random 96-bit nonce and the `user_id` as Additional Authenticated Data,
  so a ciphertext cannot be replayed against a different account.
* The DEK is itself sealed with AES-256-GCM under the *master* key (the value of
  `KMS_MASTER_KEY`), which in a real deployment is a KMS/HSM-held key and never
  lives in the database or in source control.
* `key_id` is stored per record so the master key can be rotated without a
  downtime migration: new writes use the new key id, old records keep decrypting
  with the previous one until they are next touched, at which point they are
  lazily re-wrapped.

Backwards compatibility
-----------------------
* `v2:` - the earlier AES-GCM-with-master-key-directly scheme. Still readable.
* anything else - legacy Fernet. Still readable, re-encrypted on next use.

Nothing here logs token material. Failures are logged by user id only.
"""

import base64
import json
import logging
import os
from typing import List, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config

logger = logging.getLogger("ytm_saver.crypto")

NONCE_BYTES = 12  # 96-bit nonce, the value GCM is defined for.
DEK_BYTES = 32  # AES-256

CURRENT_VERSION = "v3"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _load_master_keys() -> List[Tuple[str, bytes]]:
    """
    Master keys, newest first.

    `KMS_MASTER_KEY` is the active key. `KMS_MASTER_KEY_PREVIOUS` may contain a
    comma-separated list of `<key_id>:<base64-32-byte-key>` pairs used to decrypt
    records written before a rotation. New writes always use the active key id
    from `KMS_MASTER_KEY_ID`.
    """
    active_id = (os.getenv("KMS_MASTER_KEY_ID") or "kmk1").strip() or "kmk1"
    active_b64 = (os.getenv("KMS_MASTER_KEY") or "").strip()
    if not active_b64:
        if config.IS_PRODUCTION:
            raise RuntimeError(
                "KMS_MASTER_KEY is required in production for envelope encryption of "
                "stored Google tokens."
            )
        active_b64 = _b64e(os.urandom(DEK_BYTES))
        logger.warning(
            "KMS_MASTER_KEY not set - generated an ephemeral master key for this dev "
            "process. Tokens encrypted now will be UNREADABLE after a restart. Set "
            "KMS_MASTER_KEY explicitly for anything beyond local development."
        )
    active = _b64d(active_b64)
    if len(active) != DEK_BYTES:
        raise RuntimeError(
            "KMS_MASTER_KEY must decode to exactly %d bytes (got %d)." % (DEK_BYTES, len(active))
        )

    keys: List[Tuple[str, bytes]] = [(active_id, active)]
    for entry in (os.getenv("KMS_MASTER_KEY_PREVIOUS") or "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        key_id, _, b64 = entry.partition(":")
        try:
            previous = _b64d(b64.strip())
        except Exception:
            logger.warning("Ignoring malformed KMS_MASTER_KEY_PREVIOUS entry for %s", key_id)
            continue
        if len(previous) != DEK_BYTES:
            logger.warning("Ignoring KMS_MASTER_KEY_PREVIOUS entry %s: wrong key length", key_id)
            continue
        keys.append((key_id.strip(), previous))
    return keys


MASTER_KEYS = _load_master_keys()
ACTIVE_KEY_ID, ACTIVE_MASTER_KEY = MASTER_KEYS[0]
_MASTER_KEY_BY_ID = dict(MASTER_KEYS)

# --- Legacy key, kept only so historic Fernet ciphertext stays readable -------
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    if config.IS_PRODUCTION:
        raise RuntimeError(
            "FERNET_KEY is not set. It is required in production so that tokens "
            "encrypted by older releases can still be decrypted and lazily migrated."
        )
    FERNET_KEY = Fernet.generate_key().decode()
    logger.warning(
        "FERNET_KEY not set - generated an ephemeral legacy key for this dev process."
    )
try:
    _legacy_cipher = Fernet(FERNET_KEY.encode())
except Exception:  # pragma: no cover - misconfigured key
    if config.IS_PRODUCTION:
        raise
    _legacy_cipher = None


def _seal(data: bytes, key: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, data, aad)


def _open(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def encrypt_tokens(token_dict: dict, user_id: int) -> str:
    """
    Seal an OAuth token dictionary for `user_id`.

    The dictionary is first filtered down to `config.ALLOWED_TOKEN_FIELDS` so a
    hostile or buggy client cannot smuggle arbitrary blobs into the database.
    """
    sanitized = sanitize_token_data(token_dict)
    raw_json = json.dumps(sanitized, separators=(",", ":")).encode("utf-8")
    aad = str(user_id).encode("utf-8")

    dek = os.urandom(DEK_BYTES)
    payload_nonce, payload_ct = _seal(raw_json, dek, aad)
    dek_nonce, wrapped_dek = _seal(dek, ACTIVE_MASTER_KEY, aad)

    return ":".join(
        (
            CURRENT_VERSION,
            ACTIVE_KEY_ID,
            _b64e(wrapped_dek),
            _b64e(dek_nonce),
            _b64e(payload_nonce),
            _b64e(payload_ct),
        )
    )


def decrypt_tokens(encrypted_str: str, user_id: int) -> dict:
    """
    Unseal a stored token dictionary.

    Returns `{}` on any failure - a token we cannot read is treated as "no
    credentials", which is exactly what the existing route layer already does
    with an empty `encrypted_token_json` (it returns the same 400 body).
    """
    if not encrypted_str:
        return {}

    version, _, remainder = encrypted_str.partition(":")
    try:
        if version == CURRENT_VERSION:
            key_id, wrapped_b64, dek_nonce_b64, payload_nonce_b64, payload_ct_b64 = (
                remainder.split(":", 4)
            )
            master = _MASTER_KEY_BY_ID.get(key_id)
            if master is None:
                logger.error("No master key with id %r available for user %s", key_id, user_id)
                return {}
            aad = str(user_id).encode("utf-8")
            dek = _open(_b64d(dek_nonce_b64), _b64d(wrapped_b64), master, aad)
            plaintext = _open(
                _b64d(payload_nonce_b64), _b64d(payload_ct_b64), dek, aad
            )
            return _coerce(json.loads(plaintext.decode("utf-8")))

        if version == "v2":
            _, nonce_b64, ct_b64 = remainder.split(":", 2)
            # v2 used the master key directly with the same AAD convention.
            plaintext = _open(
                _b64d(nonce_b64), _b64d(ct_b64), MASTER_KEYS[0][1], str(user_id).encode("utf-8")
            )
            return _coerce(json.loads(plaintext.decode("utf-8")))

        # Legacy Fernet (no version prefix).
        if _legacy_cipher is None:
            return {}
        return _coerce(json.loads(_legacy_cipher.decrypt(encrypted_str.encode()).decode()))
    except Exception as exc:
        # Deliberately broad. `cryptography` raises InvalidTag on any AEAD
        # failure, which is NOT a subclass of Fernet's InvalidToken, so a
        # narrower handler here let a corrupted or tampered record escape as an
        # unhandled 500 instead of the graceful "no credentials" path.
        logger.error(
            "Failed to decrypt stored token for user %s: %s", user_id, type(exc).__name__
        )
        return {}


def needs_reencrypt(encrypted_str: str) -> bool:
    """True when the record predates the current envelope format."""
    if not encrypted_str:
        return False
    if not encrypted_str.startswith(CURRENT_VERSION + ":"):
        return True
    try:
        key_id = encrypted_str.split(":", 2)[1]
    except IndexError:
        return True
    return key_id != ACTIVE_KEY_ID


def sanitize_token_data(token_data) -> dict:
    """
    Whitelist the OAuth token fields we are willing to persist.

    Prevents an unbounded client-supplied dict from being written verbatim into
    a column, and drops anything that could later be reflected back out.
    """
    if not isinstance(token_data, dict):
        return {}
    allowed = config.ALLOWED_TOKEN_FIELDS
    cleaned = {}
    for key in allowed:
        value = token_data.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        if not value:
            continue
        cleaned[key] = value[:4096]
    return cleaned


def _coerce(loaded) -> dict:
    if isinstance(loaded, dict):
        return loaded
    return {}
