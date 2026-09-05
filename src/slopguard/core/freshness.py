"""
SlopGuard Exponential / Half-Life Freshness Engine.

Implements the age-proportional scheduling policy:
1. Packages <= 10 days old: re-audited every 10 days.
2. Packages 10 - 20 days old: re-audited every 10 days.
3. Packages > 20 days old: re-audited when 50% of elapsed lifespan has passed
   (interval = 0.5 * age_in_days), capped at a 30-day maximum interval.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional


def calculate_freshness_interval_days(
    published_at: Optional[datetime],
    now_utc: Optional[datetime] = None,
) -> float:
    """
    Calculate the next audit interval in days based on package age.

    Rules:
    - age <= 10 days: 10.0 days
    - 10 < age <= 20 days: 10.0 days
    - age > 20 days: age * 0.5 (half of elapsed lifespan), capped at 30.0 days
    """
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    elif now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)

    if published_at is None:
        return 10.0

    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=timezone.utc)

    age_seconds = max(0.0, (now_utc - published_at).total_seconds())
    age_days = age_seconds / 86400.0

    if age_days <= 10.0:
        return 10.0
    elif age_days <= 20.0:
        return 10.0
    else:
        # 50% of elapsed lifespan, capped at 30 days
        half_life_interval = age_days * 0.5
        return min(30.0, max(10.0, half_life_interval))


def calculate_next_audit_time(
    published_at: Optional[datetime],
    last_audited_at: Optional[datetime] = None,
    now_utc: Optional[datetime] = None,
) -> datetime:
    """
    Calculate the exact UTC datetime when the next freshness re-audit is due.
    """
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    elif now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=timezone.utc)

    interval_days = calculate_freshness_interval_days(published_at, now_utc=now_utc)
    base_time = last_audited_at or now_utc
    if base_time.tzinfo is None:
        base_time = base_time.replace(tzinfo=timezone.utc)

    next_due = base_time + timedelta(days=interval_days)
    return next_due.replace(microsecond=0)
