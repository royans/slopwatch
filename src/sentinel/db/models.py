"""
FlagThis Sentinel Database ORM Models.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class RegisteredPackageModel(Base):
    __tablename__ = "registered_packages"

    package_id = Column(String(36), primary_key=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    normalized_name = Column(String(255), nullable=False)
    raw_name = Column(String(255), nullable=False)
    is_brand_target = Column(Boolean, nullable=False, default=False, index=True)
    priority_score = Column(Integer, nullable=False, default=10, index=True)
    crawled_at = Column(DateTime(timezone=True), nullable=True)
    synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # True if normalized_name matches the combinatorial entity+capability+framework
    # naming grammar (sentinel.matrix.generator) — set via
    # SentinelRepository.mark_grammar_matching_packages(). Lets the historical
    # backfill crawl tier restrict itself to plausible slopsquat candidates instead
    # of indiscriminately auditing every registered package regardless of name.
    # server_default (not just default=) so raw-SQL inserts that don't mention this
    # column — bulk_sync_registered_packages uses a hand-written INSERT, not the ORM —
    # still satisfy the NOT NULL constraint at the DDL level.
    matches_grammar = Column(Boolean, nullable=False, default=False, server_default="0", index=True)

    __table_args__ = (
        UniqueConstraint("ecosystem", "normalized_name", name="uq_eco_pkg_name"),
        Index("idx_registered_eco_name", "ecosystem", "normalized_name"),
        Index("idx_registered_priority", "is_brand_target", "priority_score", "synced_at"),
        Index("idx_registered_grammar_backfill", "ecosystem", "matches_grammar", "crawled_at"),
    )


class UnregisteredWatchlistModel(Base):
    __tablename__ = "unregistered_watchlist"

    candidate_id = Column(String(36), primary_key=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    normalized_name = Column(String(255), nullable=False)
    entity_token = Column(String(128), nullable=False, index=True)
    capability_token = Column(String(128), nullable=False)
    framework_token = Column(String(128), nullable=False)
    risk_weight = Column(Integer, nullable=False, default=50)
    state = Column(String(32), nullable=False, default="WATCHING", index=True)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    detections = relationship("SquatDetectionModel", back_populates="candidate", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("ecosystem", "normalized_name", name="uq_watchlist_eco_name"),
        Index("idx_watchlist_lookup", "ecosystem", "normalized_name", "state"),
    )


class SquatDetectionModel(Base):
    __tablename__ = "squat_detections"

    detection_id = Column(String(36), primary_key=True)
    candidate_id = Column(String(36), ForeignKey("unregistered_watchlist.candidate_id"), nullable=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    author_username = Column(String(255), nullable=True)
    release_version = Column(String(64), nullable=False, default="0.1.0")
    published_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0), index=True)
    threat_score = Column(Integer, nullable=False, default=0)
    analysis_details_json = Column(Text, nullable=True)
    is_exported_to_flagthis = Column(Boolean, nullable=False, default=False)
    verdict = Column(String(32), nullable=False, default="MALICIOUS")
    content_hash = Column(String(64), nullable=True)
    priority_tier = Column(Integer, nullable=False, default=2)
    audit_count = Column(Integer, nullable=False, default=1)
    last_audited_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0), nullable=False)
    next_audit_due_at = Column(DateTime(timezone=True), nullable=True, index=True)
    # Reprocessing & Re-audit Lifecycle Flags
    needs_reprocess = Column(Boolean, nullable=False, default=False, index=True)
    refresh_network_data = Column(Boolean, nullable=False, default=False)
    reprocess_priority = Column(Integer, nullable=False, default=100, index=True)
    reprocess_reason = Column(String(128), nullable=True)

    # Structured, indexed "can this package run code at install/deploy time" fields —
    # mirrors analysis_details_json.{has_install_hook,has_network_socket} so the
    # frontend/UI can filter by them directly instead of scanning the JSON blob.
    # Names match the internal downstream sync table's generated columns of the same name.
    has_install_hook = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    has_network_socket = Column(Boolean, nullable=False, default=False, server_default="0", index=True)

    # Registry deprecation & package abandonment status
    is_deprecated = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    deprecation_reason = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0), onupdate=lambda: datetime.now(timezone.utc).replace(microsecond=0), nullable=False)

    candidate = relationship("UnregisteredWatchlistModel", back_populates="detections")

    __table_args__ = (
        UniqueConstraint("ecosystem", "package_name", name="uq_eco_pkg_detection"),
        Index("idx_detection_eco_pkg", "ecosystem", "package_name"),
        Index("idx_detection_version", "release_version"),
        Index("idx_detection_updated_at", "updated_at"),
        Index("idx_detection_next_audit", "next_audit_due_at"),
        Index("idx_detection_reprocess", "needs_reprocess", "reprocess_priority"),
        Index("idx_detection_install_hook", "ecosystem", "has_install_hook", "threat_score"),
    )


class SignalFindingModel(Base):
    """
    One row per (detection, signal) — the normalized, query-anywhere detection
    layer. ``signal_code`` is *data*, not a column, so adding a brand-new detector
    signal never requires a migration: "find every package with signal X" is a
    single indexed equality lookup here, and the UI facet list is built from
    ``SELECT signal_code, COUNT(*) ... GROUP BY signal_code``.

    ``threat_score`` / ``verdict`` / ``published_at`` are denormalized from the
    parent detection so a single-facet filtered + sorted feed query never has to
    touch ``squat_detections`` until it hydrates the final page of rows.
    """
    __tablename__ = "sentinel_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    detection_id = Column(String(36), ForeignKey("squat_detections.detection_id", ondelete="CASCADE"), nullable=False)
    ecosystem = Column(String(32), nullable=False)
    package_name = Column(String(255), nullable=False)

    signal_code = Column(String(64), nullable=False)
    category = Column(String(32), nullable=False, default="GENERAL")
    severity = Column(String(16), nullable=False, default="MEDIUM")
    severity_rank = Column(Integer, nullable=False, default=2)
    score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=100)   # stored as 0-100 int
    kind = Column(String(16), nullable=False, default="ASSESSMENT")
    detector = Column(String(64), nullable=False, default="unknown")
    is_code_execution = Column(Boolean, nullable=False, default=False)
    gates_malicious = Column(Boolean, nullable=False, default=False)
    metadata_json = Column(Text, nullable=True)

    # denormalized parent columns for fast filtered feeds
    threat_score = Column(Integer, nullable=False, default=0)
    verdict = Column(String(32), nullable=False, default="SUSPICIOUS")
    published_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0))

    __table_args__ = (
        UniqueConstraint("detection_id", "signal_code", name="uq_finding_detection_signal"),
        Index("idx_finding_signal_feed", "signal_code", "threat_score"),
        Index("idx_finding_signal_recent", "signal_code", "published_at"),
        Index("idx_finding_pkg", "ecosystem", "package_name"),
        Index("idx_finding_category", "category", "severity_rank"),
        Index("idx_finding_detection", "detection_id"),
    )


class ScanAuditLogModel(Base):
    __tablename__ = "scan_audit_log"

    scan_id = Column(String(36), primary_key=True)
    target_path = Column(String(512), nullable=False)
    ecosystem = Column(String(32), nullable=False)
    total_dependencies = Column(Integer, nullable=False, default=0)
    flagged_count = Column(Integer, nullable=False, default=0)
    scanned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0))


class DailyReviewLogModel(Base):
    """
    Enforcement & audit trail for the 'at most one review per package per UTC day' rule.
    One row per (ecosystem, package_name, review_date); review_count tracks how many
    times a review was *attempted* that day (only the first attempt is ever allowed
    to proceed — see SentinelRepository.try_claim_daily_review).
    """
    __tablename__ = "daily_review_log"

    ecosystem = Column(String(32), primary_key=True)
    package_name = Column(String(255), primary_key=True)
    review_date = Column(String(10), primary_key=True)  # UTC date, YYYY-MM-DD
    review_count = Column(Integer, nullable=False, default=1)
    first_reviewed_at = Column(DateTime(timezone=True), nullable=False)
    last_attempted_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("idx_daily_review_date", "review_date"),
    )


class PersistentJobQueueModel(Base):
    __tablename__ = "sentinel_jobs_queue"

    job_id = Column(String(36), primary_key=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    job_type = Column(String(64), nullable=False, default="RECALCULATE_SCORE", index=True)
    priority = Column(Integer, nullable=False, default=100, index=True)
    status = Column(String(32), nullable=False, default="PENDING", index=True)
    refresh_network_data = Column(Boolean, nullable=False, default=False)
    attempts = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)
    leased_until = Column(DateTime(timezone=True), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    payload_json = Column(Text, nullable=True)
    enqueued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc).replace(microsecond=0), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("ecosystem", "package_name", "job_type", name="uq_job_eco_pkg_type"),
        Index("idx_jobs_status_priority", "status", "priority", "leased_until"),
        Index("idx_jobs_pkg", "ecosystem", "package_name"),
    )


