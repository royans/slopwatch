"""
Sentinel Data Transfer Objects (DTOs) & Enums.

Defines the multi-ecosystem data structures for tracking packages,
watchlist candidates, security analysis results, and threat detections.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class Ecosystem(str, Enum):
    """Supported package registry ecosystems."""
    PYPI = "pypi"
    NPM = "npm"
    CARGO = "cargo"
    PACKAGIST = "packagist"
    RUBYGEMS = "rubygems"


class WatchlistState(str, Enum):
    """Lifecycle states of a generated watchlist candidate."""
    WATCHING = "WATCHING"
    SQUATTED = "SQUATTED"


class ThreatVerdict(str, Enum):
    """Verdict classification for a detected package."""
    VERIFIED_OFFICIAL = "VERIFIED_OFFICIAL"    # Published by verified brand author domain
    BENIGN_COMMUNITY = "BENIGN_COMMUNITY"      # Legitimate high-effort community library
    SQUATTED_STUB = "SQUATTED_STUB"            # Empty package, 0 code, name reservation
    SUSPICIOUS = "SUSPICIOUS"                  # Anomalous metadata, unverified author, low effort
    MALICIOUS = "MALICIOUS"                    # Verified install-time hooks, reverse shell, curl|bash
    # The point score crossed the SUSPICIOUS/MALICIOUS threshold, but every
    # contributing signal is individually low/medium-confidence (see
    # core/confidence.py) — real signal, not yet strong enough on its own to
    # confidently assert malice. Confirmed real-world cases this protects
    # against: `playwright`, `agentdiscover` (both legitimate, both would
    # otherwise show SUSPICIOUS/"POTENTIALLY MALICIOUS").
    UNVERIFIED_HIGH_SIGNAL = "UNVERIFIED_HIGH_SIGNAL"


class EvidenceSignal(BaseModel):
    """A structured, machine-readable forensic evidence signal."""
    signal_id: str
    category: str = "GENERAL"                  # NAMING_HEURISTIC, VENDOR_AUTHENTICITY, CODE_ANALYSIS, NETWORK_BEHAVIOR
    severity: str = "MEDIUM"                   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    score_impact: int = 0
    rule_code: str = "RULE_GENERIC"
    human_description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_critical: bool = False

    # Backward compatibility helper
    @property
    def name(self) -> str:
        return self.signal_id

    @property
    def observed_detail(self) -> str:
        return self.human_description




class RegisteredPackage(BaseModel):
    """A verified package currently registered in the upstream registry."""
    package_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ecosystem: Ecosystem
    normalized_name: str
    raw_name: str
    synced_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WatchlistCandidate(BaseModel):
    """An unregistered long-tail candidate being monitored."""
    candidate_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ecosystem: Ecosystem
    normalized_name: str
    entity_token: str
    capability_token: str
    framework_token: str
    risk_weight: int = Field(ge=1, le=100, default=50)
    state: WatchlistState = WatchlistState.WATCHING
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PackageCreationEvent(BaseModel):
    """An event observed on the registry stream indicating a newly created package."""
    ecosystem: Ecosystem
    package_name: str
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    author_username: Optional[str] = None
    release_version: Optional[str] = None


class ASTSecurityReport(BaseModel):
    """Static AST and manifest security inspection report."""
    has_socket: bool = False
    has_subprocess: bool = False
    has_os_system: bool = False
    has_base64_eval: bool = False
    has_lifecycle_scripts: bool = False
    has_pth_execution: bool = False
    has_exfiltration_destination: bool = False
    has_credential_harvesting: bool = False
    has_bundled_binary: bool = False
    has_dynamic_obfuscation: bool = False
    total_source_files: int = 0
    total_lines_of_code: int = 0
    total_code_size_bytes: int = 0
    is_empty_stub: bool = False
    code_size_tier: str = "UNKNOWN"
    flags: List[str] = Field(default_factory=list)
    line_details: List[str] = Field(default_factory=list)
    composite_threat_score: int = Field(ge=0, le=100, default=0)
    verdict: ThreatVerdict = ThreatVerdict.BENIGN_COMMUNITY




class PackageMetadata(BaseModel):
    """Metadata retrieved from the registry JSON API."""
    ecosystem: Ecosystem
    package_name: str
    latest_version: str
    author: Optional[str] = None
    author_email: Optional[str] = None
    homepage: Optional[str] = None
    project_urls: Dict[str, str] = Field(default_factory=dict)
    description: Optional[str] = None
    tarball_url: Optional[str] = None
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_published_at: Optional[datetime] = None
    latest_release_at: Optional[datetime] = None
    release_count: int = 1
    has_rapid_semver_burst: bool = False
    monthly_downloads: int = 0
    weekly_downloads: int = 0
    daily_downloads: int = 0
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None



def format_iso_seconds(dt: Optional[datetime] = None) -> str:
    """Format datetime in UTC with second-level ISO-8601 precision (YYYY-MM-DDTHH:MM:SSZ)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class SquatDetection(BaseModel):
    """A detected threat or anomalous slopsquatted package."""
    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    candidate_id: Optional[str] = None
    ecosystem: Ecosystem
    package_name: str
    author_username: Optional[str] = None
    release_version: Optional[str] = "0.1.0"
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    first_published_at: Optional[datetime] = None
    latest_release_at: Optional[datetime] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    last_audited_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    threat_score: int = Field(default=0, ge=0, le=1000)
    analysis_details: Dict[str, Any] = Field(default_factory=dict)
    is_exported: bool = False
    verdict: ThreatVerdict = ThreatVerdict.SUSPICIOUS
    content_hash: Optional[str] = None
    priority_tier: int = 2
    audit_count: int = 1
    next_audit_due_at: Optional[datetime] = None
    is_deprecated: bool = False
    deprecation_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))

