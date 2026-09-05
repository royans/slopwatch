from datetime import datetime, timezone, timedelta
from slopwatch.core.freshness import calculate_freshness_interval_days, calculate_next_audit_time


def test_freshness_interval_under_10_days():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    
    # 2 days old
    pub_dt = now_utc - timedelta(days=2)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 10.0

    # 9 days old
    pub_dt = now_utc - timedelta(days=9)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 10.0


def test_freshness_interval_between_10_and_20_days():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    
    # 15 days old -> 10 days
    pub_dt = now_utc - timedelta(days=15)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 10.0


def test_freshness_interval_over_20_days():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    
    # 40 days old -> 50% = 20 days
    pub_dt = now_utc - timedelta(days=40)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 20.0

    # 80 days old -> 50% = 40 days, capped at 30 days
    pub_dt = now_utc - timedelta(days=80)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 30.0


def test_calculate_next_audit_time():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    pub_dt = now_utc - timedelta(days=40)
    
    next_due = calculate_next_audit_time(pub_dt, last_audited_at=now_utc, now_utc=now_utc)
    assert next_due == now_utc + timedelta(days=20)
