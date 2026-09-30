"""
YouTube Data API quota accounting, per-user budgets and the circuit breaker.

Design rules
------------
1. Quota is reserved *before* the HTTP call, not after. A request that fails
   still consumes units, so reserving up front is the only way a hard cap can
   actually hold. The reservation is deliberately not refunded.
2. Every mutation is a single atomic SQL statement (INSERT .. ON CONFLICT DO
   UPDATE) so that concurrent workers cannot both pass a cap check and then
   both spend. There is no read-modify-write window.
3. The "day" is a Pacific calendar day because that is when Google resets the
   project quota.
4. Nothing in this module changes the HTTP contract. A refusal raises
   `QuotaBudgetExceeded`, and the route layer renders it as the same 502 body
   the extension already handles.
"""

import datetime
import logging
from typing import Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

import config
import models

logger = logging.getLogger("ytm_saver.quota")


# --- Pacific-time helpers -----------------------------------------------------
_PT_STD_OFFSET = datetime.timedelta(hours=8)  # PST
try:  # pragma: no cover - depends on the host having a tz database
    from zoneinfo import ZoneInfo

    _PT_ZONE = ZoneInfo("America/Los_Angeles")
except Exception:  # pragma: no cover - Windows without tzdata, containers, etc.
    _PT_ZONE = None


def pacific_now(now: Optional[datetime.datetime] = None) -> datetime.datetime:
    """Current time expressed in America/Los_Angeles (DST aware when possible)."""
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    if _PT_ZONE is not None:
        return now.astimezone(_PT_ZONE)
    # Fallback: fixed PST offset. Up to an hour of drift at the day boundary on
    # hosts without a tz database, which is the same behaviour as before.
    return now.astimezone(datetime.timezone(-_PT_STD_OFFSET))


def quota_day_str(now: Optional[datetime.datetime] = None) -> str:
    """`YYYY-MM-DD` in Pacific time - the key used for daily quota rows."""
    return pacific_now(now).strftime("%Y-%m-%d")


def seconds_until_quota_reset(now: Optional[datetime.datetime] = None) -> int:
    """Seconds until the next Pacific midnight, when the quota refills."""
    pt_now = pacific_now(now)
    tomorrow = (pt_now + datetime.timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return max(int((tomorrow - pt_now).total_seconds()), 0)


# --- Exceptions ---------------------------------------------------------------
class QuotaBudgetExceeded(RuntimeError):
    """A quota budget is exhausted. Rendered to the client as HTTP 502."""

    scope = "quota"

    def __init__(self, message: str, *, scope: str = None, usage: int = 0, cap: int = 0):
        super().__init__(message)
        # `scope` is a class attribute on each subclass; only fall back to it
        # when the caller did not pass one explicitly.
        self.scope = scope or type(self).scope
        self.usage = usage
        self.cap = cap


class GlobalQuotaExceeded(QuotaBudgetExceeded):
    scope = "global"


class UserQuotaExceeded(QuotaBudgetExceeded):
    scope = "user"


class YouTubeQuotaDepleted(QuotaBudgetExceeded):
    """YouTube itself answered 403 quotaExceeded / 429 Too Many Requests."""

    scope = "upstream"


class PlaylistDeletedError(RuntimeError):
    """The cached playlist ID no longer resolves (user deleted it)."""


# --- Dialect-aware atomic helpers --------------------------------------------
def _updating_insert(session: Session):
    """Return an `INSERT` construct with ON CONFLICT support, or None."""
    bind = session.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as _insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as _insert
    else:
        return None
    return _insert


# Threshold crossings already announced by this process, keyed by
# (label, scope, user_id, quota_day). This is module-level on purpose: the
# service builds a fresh QuotaTracker per access, so an instance attribute
# would re-announce on every reserved unit and flood the logs.
_ALERTED: set = set()


class QuotaTracker:
    """Atomic daily quota ledger backed by the `quota_usage` table."""

    def __init__(self, db: Session, date_str: Optional[str] = None):
        self.db = db
        self.date_str = date_str or quota_day_str()
        self._warned: set = _ALERTED

    # -- reads ---------------------------------------------------------------
    def global_usage(self) -> int:
        if self.db is None:
            return 0
        total = (
            self.db.execute(
                select(func.coalesce(func.sum(models.QuotaUsage.units_used), 0)).where(
                    models.QuotaUsage.date_str == self.date_str
                )
            ).scalar()
            or 0
        )
        return int(total)

    def user_usage(self, user_id: int) -> int:
        if not user_id or self.db is None:
            return 0
        row = self.db.execute(
            select(models.QuotaUsage.units_used).where(
                models.QuotaUsage.date_str == self.date_str,
                models.QuotaUsage.user_id == user_id,
            )
        ).first()
        return int(row[0]) if row else 0

    def user_playlists_created(self, user_id: int) -> int:
        if not user_id or self.db is None:
            return 0
        row = self.db.execute(
            select(models.QuotaUsage.playlists_created).where(
                models.QuotaUsage.date_str == self.date_str,
                models.QuotaUsage.user_id == user_id,
            )
        ).first()
        return int(row[0]) if row and row[0] is not None else 0

    def snapshot(self, user_id: int) -> Tuple[int, int]:
        return self.global_usage(), self.user_usage(user_id)

    # -- budget gate ---------------------------------------------------------
    def ensure_budget(
        self,
        user_id: int,
        projected_units: int = 0,
        *,
        global_cap: Optional[int] = None,
        user_cap: Optional[int] = None,
    ) -> None:
        """Raise before spending if the reservation would cross a cap."""
        global_cap = config.QUOTA_GLOBAL_CAP if global_cap is None else global_cap
        user_cap = config.QUOTA_PER_USER_CAP if user_cap is None else user_cap
        projected_units = max(int(projected_units or 0), 0)

        g_used = self.global_usage()
        if g_used + projected_units > global_cap:
            raise GlobalQuotaExceeded(
                "Global daily YouTube API quota exceeded. Please try again later today.",
                usage=g_used,
                cap=global_cap,
            )

        if user_id:
            u_used = self.user_usage(user_id)
            if u_used + projected_units > user_cap:
                raise UserQuotaExceeded(
                    "Your personal daily YouTube API quota has been exceeded. "
                    "Please try again later today.",
                    usage=u_used,
                    cap=user_cap,
                )

    def ensure_can_create_playlist(self, user_id: int) -> None:
        created = self.user_playlists_created(user_id)
        if created >= config.MAX_PLAYLIST_CREATES_PER_USER_PER_DAY:
            raise UserQuotaExceeded(
                "Too many playlists created today. Please try again later today.",
                usage=created,
                cap=config.MAX_PLAYLIST_CREATES_PER_USER_PER_DAY,
            )

    # -- atomic reservation --------------------------------------------------
    def reserve(self, user_id: int, units: int, *, method: str = "") -> int:
        """
        Atomically add `units` to today's ledger for `user_id`.

        Returns the user's new running total. `method` is only used for audit
        logging. The reservation is never refunded: Google charges the units
        whether or not the call succeeded.
        """
        units = int(units)
        if units <= 0 or self.db is None:
            return self.user_usage(user_id)
        if not user_id:
            # Global spend with no attributable user (should not happen for
            # authenticated routes) is still counted so the cap holds.
            logger.debug("quota.reserve called without user_id; units=%s", units)
            return self.global_usage()

        statement_builder = _updating_insert(self.db)
        row = None
        if statement_builder is not None:
            stmt = (
                statement_builder(models.QuotaUsage)
                .values(
                    date_str=self.date_str,
                    user_id=user_id,
                    units_used=units,
                    playlists_created=0,
                )
                .on_conflict_do_update(
                    index_elements=[
                        models.QuotaUsage.date_str,
                        models.QuotaUsage.user_id,
                    ],
                    set_={"units_used": models.QuotaUsage.units_used + units},
                )
                .returning(models.QuotaUsage.units_used)
            )
            row = self.db.execute(stmt).first()
        else:  # pragma: no cover - only for exotic dialects
            existing = (
                self.db.query(models.QuotaUsage)
                .filter_by(date_str=self.date_str, user_id=user_id)
                .with_for_update()
                .first()
            )
            if existing is None:
                existing = models.QuotaUsage(
                    date_str=self.date_str, user_id=user_id, units_used=0
                )
                self.db.add(existing)
            existing.units_used += units
            row = (existing.units_used,)

        try:
            self.db.commit()
        except Exception:  # pragma: no cover - ledger must never break a request
            self.db.rollback()
            logger.exception("Failed to persist quota reservation (%s, %s units)", method, units)
            return self.user_usage(user_id)

        total = int(row[0]) if row else 0
        logger.info(
            "quota.reserve method=%s units=%s user=%s user_total=%s",
            method or "unknown",
            units,
            user_id,
            total,
        )
        self.maybe_alert(user_id)
        return total

    def record_playlist_created(self, user_id: int) -> None:
        """Atomically bump the per-user playlist-creation counter."""
        if not user_id or self.db is None:
            return
        statement_builder = _updating_insert(self.db)
        if statement_builder is not None:
            stmt = (
                statement_builder(models.QuotaUsage)
                .values(
                    date_str=self.date_str,
                    user_id=user_id,
                    units_used=0,
                    playlists_created=1,
                )
                .on_conflict_do_update(
                    index_elements=[
                        models.QuotaUsage.date_str,
                        models.QuotaUsage.user_id,
                    ],
                    set_={
                        "playlists_created": models.QuotaUsage.playlists_created + 1
                    },
                )
            )
            self.db.execute(stmt)
        else:  # pragma: no cover
            existing = (
                self.db.query(models.QuotaUsage)
                .filter_by(date_str=self.date_str, user_id=user_id)
                .first()
            )
            if existing is None:
                existing = models.QuotaUsage(date_str=self.date_str, user_id=user_id)
                self.db.add(existing)
            existing.playlists_created = (existing.playlists_created or 0) + 1
        try:
            self.db.commit()
        except Exception:  # pragma: no cover
            self.db.rollback()
            logger.exception("Failed to record playlist creation for user %s", user_id)

    # -- alerting ------------------------------------------------------------
    def maybe_alert(self, user_id: int) -> None:
        """Emit a single audit warning per (user, threshold) per process."""
        g_used, u_used = self.snapshot(user_id)
        for label, pct in (
            ("warn", config.QUOTA_ALERT_WARN_PCT),
            ("critical", config.QUOTA_ALERT_CRIT_PCT),
        ):
            if pct <= 0:
                continue
            g_pct = (g_used / config.QUOTA_GLOBAL_CAP * 100) if config.QUOTA_GLOBAL_CAP else 0
            u_pct = (u_used / config.QUOTA_PER_USER_CAP * 100) if config.QUOTA_PER_USER_CAP else 0
            if max(g_pct, u_pct) >= pct:
                # Keyed by quota day so a new Pacific day re-arms the alerts.
                key = (label, self.date_str, user_id)
                if key not in self._warned:
                    self._warned.add(key)
                    logger.warning(
                        "QUOTA %s: global=%s/%s (%.0f%%) user=%s/%s (%.0f%%) reset_in=%ss",
                        label,
                        g_used,
                        config.QUOTA_GLOBAL_CAP,
                        g_pct,
                        u_used,
                        config.QUOTA_PER_USER_CAP,
                        u_pct,
                        seconds_until_quota_reset(),
                    )


def estimate_restore_units(track_count: int, *, needs_playlist_create: bool, needs_sync: bool,
                           items_to_insert: int, sync_pages: int = 1) -> int:
    """
    Upper bound on the units one restore can spend. Used for the fail-fast
    pre-flight check so a doomed request never issues a single call.
    """
    units = 0
    if needs_playlist_create:
        units += config.ytm_unit_cost("playlists.insert")
    else:
        units += config.ytm_unit_cost("playlists.list")
    if needs_sync:
        units += sync_pages * config.ytm_unit_cost("playlistItems.list")
    if config.FLAG_VALIDATE_VIDEO_IDS:
        units += max(1, -(-track_count // 50)) * config.ytm_unit_cost("videos.list")
    units += max(0, items_to_insert) * config.ytm_unit_cost("playlistItems.insert")
    return units
