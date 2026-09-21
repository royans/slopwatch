"""
Sentinel Base Registry Adapter Interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Set, List, Optional
from slopwatch.core.dto import (
    Ecosystem,
    PackageCreationEvent,
    PackageMetadata,
    ASTSecurityReport,
)


@dataclass
class RegistryChange:
    """All changes to one package inside a fetched slice of a registry change stream."""
    name: str
    first_seq: int
    last_seq: int
    is_new: bool = False             # the package was created in this slice
    deleted: bool = False
    is_release: bool = True          # a new release/revision (False: e.g. only extra files for an old release)
    version: Optional[str] = None    # newest release seen, when the stream carries it (PyPI); npm does not
    created_at: Optional[datetime] = None  # registry-side creation time, when the stream carries it


@dataclass
class RegistryChangesPage:
    changes: List[RegistryChange]
    last_seq: str                    # resume here next time
    raw_count: int                   # raw stream entries consumed (a full page means more remain)


class BaseRegistryAdapter(ABC):
    """Abstract base class for all package registry adapters."""

    @property
    @abstractmethod
    def ecosystem(self) -> Ecosystem:
        """Return the ecosystem identifier."""
        pass

    @abstractmethod
    def normalize_name(self, raw_name: str) -> str:
        """Normalize package name according to ecosystem standard (e.g. PEP 503 for PyPI)."""
        pass

    @abstractmethod
    async def fetch_full_catalog(self) -> Set[str]:
        """Download and stream the complete catalog of registered package names."""
        pass

    @abstractmethod
    async def fetch_recent_creations(self, limit: int = 50) -> List[PackageCreationEvent]:
        """Fetch stream of newly created packages published in the recent window."""
        pass

    @abstractmethod
    async def inspect_package_metadata(self, package_name: str) -> Optional[PackageMetadata]:
        """Fetch metadata, release versions, and tarball URLs from registry API."""
        pass

    @abstractmethod
    async def download_and_inspect_payload(self, package_name: str, version: Optional[str] = None) -> ASTSecurityReport:
        """Download package payload and perform static security inspection."""
        pass
