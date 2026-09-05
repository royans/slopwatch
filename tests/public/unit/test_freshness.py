from datetime import datetime, timezone, timedelta
from sentinel.scheduler.freshness import calculate_freshness_interval_days, calculate_next_audit_time


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


def test_freshness_interval_over_20_days_half_life():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    
    # 24 days old -> 12 days (50%)
    pub_dt = now_utc - timedelta(days=24)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 12.0

    # 40 days old -> 20 days (50%)
    pub_dt = now_utc - timedelta(days=40)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 20.0

    # 50 days old -> 25 days (50%)
    pub_dt = now_utc - timedelta(days=50)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 25.0


def test_freshness_interval_capped_at_30_days():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    
    # 80 days old -> 50% is 40, but capped at 30 days
    pub_dt = now_utc - timedelta(days=80)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 30.0

    # 365 days old -> capped at 30 days
    pub_dt = now_utc - timedelta(days=365)
    interval = calculate_freshness_interval_days(pub_dt, now_utc=now_utc)
    assert interval == 30.0


def test_calculate_next_audit_time():
    now_utc = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    pub_dt = now_utc - timedelta(days=40)  # 40 days -> 20 day interval
    
    next_due = calculate_next_audit_time(pub_dt, last_audited_at=now_utc, now_utc=now_utc)
    expected = now_utc + timedelta(days=20)
    assert next_due == expected
