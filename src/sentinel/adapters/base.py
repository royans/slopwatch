"""
FlagThis Sentinel Base Registry Adapter Interface.
"""

from abc import ABC, abstractmethod
from typing import Set, List, Optional
from sentinel.core.dto import (
    Ecosystem,
    PackageCreationEvent,
    PackageMetadata,
    ASTSecurityReport,
)


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
