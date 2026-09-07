"""
SlopWatch Dynamic Domain Trustworthiness Engine.

Computes objective, empirical trustworthiness scores (0.0 to 1.0) for author
email domains based on:
1. Package volume (breadth of catalog)
2. Publication span / longevity (time between first and latest package)
3. Recency / Dropcatch protection (activity in the last 365 days)
4. Absence of historical malicious activity
5. Exclusion of shared public ESPs (Gmail, Yahoo, Outlook, etc.)
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, Optional, Set
from pydantic import BaseModel, Field

from slopwatch.core.taxonomies import (
    PUBLIC_EMAIL_PROVIDERS,
    DISPOSABLE_EMAIL_DOMAINS,
    TRUSTED_VENDORS,
)


GENERIC_NON_CUSTOM_DOMAINS: Set[str] = frozenset(
    set(PUBLIC_EMAIL_PROVIDERS)
    | set(DISPOSABLE_EMAIL_DOMAINS)
    | {
        "example.com",
        "users.noreply.github.com",
        "github.com",
        "localhost",
        "none",
        "test.com",
        "temp.com",
        "<unknown>",
        "<missing>",
        "email.com",
        "mail.ru",
        "googlegroups.com",
        "yandex.ru",
        "yandex.com",
        "rambler.ru",
        "163.com",
        "126.com",
        "sina.com",
        "gmx.com",
        "gmx.net",
        "zoho.com",
    }
)


class DomainReputation(BaseModel):
    """Empirical reputation and activity metrics for an author email domain."""

    domain: str
    package_count: int = 1
    span_days: int = 0
    days_since_latest: int = 0
    total_age_days: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    is_custom_domain: bool = True
    trust_score: float = 0.0
    first_published_at: Optional[datetime] = None
    latest_published_at: Optional[datetime] = None

    @property
    def is_generic_esp(self) -> bool:
        return not self.is_custom_domain

    @property
    def has_malware(self) -> bool:
        return self.malicious_count > 0


class DomainTrustEngine:
    """Thread-safe dynamic domain trustworthiness scoring and caching engine."""

    def __init__(self, preloaded_reputations: Optional[Dict[str, DomainReputation]] = None):
        self._lock = threading.RLock()
        self._cache: Dict[str, DomainReputation] = dict(preloaded_reputations or {})

    @staticmethod
    def is_custom_domain(domain: str) -> bool:
        """Check if domain is a custom organizational domain rather than a shared/public ESP."""
        if not domain:
            return False
        clean = domain.lower().strip()
        return clean not in GENERIC_NON_CUSTOM_DOMAINS

    @classmethod
    def compute_trust_score(
        cls,
        package_count: int,
        span_days: int,
        days_since_latest: int,
        malicious_count: int = 0,
        is_custom: bool = True,
    ) -> float:
        """
        Compute normalized trustworthiness score between 0.0 and 1.0.

        Formula:
          Base Eligibility: is_custom AND malicious_count == 0
          Volume Factor V: min(1.0, package_count / 10.0)
          Longevity Factor S: min(1.0, span_days / 365.0)
          Recency Factor R:
            - If days_since_latest <= 365 -> 1.0
            - If 365 < days_since_latest <= 730 -> max(0.2, 1.0 - (days_since_latest - 365) / 365)
            - If > 730 -> 0.2 (decayed for dormant / potentially expired domains)

          TrustScore = round((0.4 * V + 0.6 * S) * R, 3)
        """
        if not is_custom or malicious_count > 0:
            return 0.0

        if package_count <= 0:
            return 0.0

        # 1. Volume Factor (saturates at 10 packages)
        v = min(1.0, package_count / 10.0)

        # 2. Longevity / Span Factor (saturates at 365 days)
        # S represents publication breadth across time; 0 for single-day bursts
        s = min(1.0, max(0, span_days) / 365.0)

        # 3. Recency / Dropcatch Factor
        if days_since_latest <= 365:
            r = 1.0
        elif days_since_latest <= 730:
            r = max(0.2, 1.0 - (days_since_latest - 365) / 365.0)
        else:
            r = 0.2

        # Weighted composite: longevity is weighted higher than volume (time cannot be faked)
        raw_trust = (0.4 * v + 0.6 * s) * r
        return round(min(1.0, max(0.0, raw_trust)), 3)

    def get_domain_reputation(self, domain: Optional[str]) -> Optional[DomainReputation]:
        """Look up cached reputation for a domain."""
        if not domain:
            return None
        clean = domain.lower().strip()
        with self._lock:
            return self._cache.get(clean)

    def set_domain_reputation(self, reputation: DomainReputation) -> None:
        """Store or update a domain reputation in the cache."""
        clean = reputation.domain.lower().strip()
        with self._lock:
            self._cache[clean] = reputation

    register_reputation = set_domain_reputation

    def update_reputations_bulk(self, reps: Dict[str, DomainReputation]) -> None:
        """Bulk load or update reputations."""
        with self._lock:
            for k, v in reps.items():
                self._cache[k.lower().strip()] = v

    def evaluate_domain(
        self,
        domain: str,
        package_count: int,
        first_published_at: Optional[datetime],
        latest_published_at: Optional[datetime],
        malicious_count: int = 0,
        suspicious_count: int = 0,
        now: Optional[datetime] = None,
    ) -> DomainReputation:
        """Calculate and cache reputation for a domain from raw dates and counts."""
        clean = domain.lower().strip()
        is_custom = self.is_custom_domain(clean)
        now_dt = now or datetime.now(timezone.utc)

        span_days = 0
        days_since_latest = 0
        total_age_days = 0

        if first_published_at and latest_published_at:
            span_days = max(0, (latest_published_at - first_published_at).days)
            days_since_latest = max(0, (now_dt - latest_published_at).days)
            total_age_days = max(0, (now_dt - first_published_at).days)
        elif latest_published_at:
            days_since_latest = max(0, (now_dt - latest_published_at).days)
            total_age_days = days_since_latest
        elif first_published_at:
            total_age_days = max(0, (now_dt - first_published_at).days)
            days_since_latest = total_age_days

        trust = self.compute_trust_score(
            package_count=package_count,
            span_days=span_days,
            days_since_latest=days_since_latest,
            malicious_count=malicious_count,
            is_custom=is_custom,
        )

        rep = DomainReputation(
            domain=clean,
            package_count=package_count,
            span_days=span_days,
            days_since_latest=days_since_latest,
            total_age_days=total_age_days,
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            is_custom_domain=is_custom,
            trust_score=trust,
            first_published_at=first_published_at,
            latest_published_at=latest_published_at,
        )
        self.set_domain_reputation(rep)
        return rep


# Global shared engine instance
_SHARED_ENGINE: Optional[DomainTrustEngine] = None
_INIT_LOCK = threading.Lock()


def get_shared_domain_trust_engine() -> DomainTrustEngine:
    """Get or lazily initialize process-wide DomainTrustEngine."""
    global _SHARED_ENGINE
    if _SHARED_ENGINE is None:
        with _INIT_LOCK:
            if _SHARED_ENGINE is None:
                _SHARED_ENGINE = DomainTrustEngine()
    return _SHARED_ENGINE
