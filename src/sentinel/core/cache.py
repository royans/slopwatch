"""
FlagThis Sentinel Local Disk Cache Manager.

Provides zero-network caching for upstream package catalogs, registry metadata,
and downloaded tarball payloads with configurable TTL and eviction policies.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Any, Dict, Set


class DiskCacheManager:
    def __init__(self, cache_root: Path = Path("data/cache")):
        self.cache_root = Path(cache_root)
        self.catalogs_dir = self.cache_root / "catalogs"
        self.metadata_dir = self.cache_root / "metadata"
        self.payloads_dir = self.cache_root / "payloads"

        for d in [self.catalogs_dir, self.metadata_dir, self.payloads_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ==================== Full Catalog Cache ====================

    def get_cached_catalog(self, ecosystem: str, ttl_seconds: float = 86400.0) -> Optional[Set[str]]:
        """Retrieve full package catalog from disk if within TTL (default: 24 hours)."""
        cache_file = self.catalogs_dir / f"{ecosystem}_catalog.json"
        if not cache_file.exists():
            return None

        mtime = cache_file.stat().st_mtime
        if (time.time() - mtime) > ttl_seconds:
            return None  # Expired

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            return set(data)
        except Exception:
            return None

    def save_cached_catalog(self, ecosystem: str, package_names: Set[str]) -> None:
        """Persist full package catalog to disk cache."""
        cache_file = self.catalogs_dir / f"{ecosystem}_catalog.json"
        cache_file.write_text(json.dumps(list(package_names)), encoding="utf-8")

    # ==================== Registry Metadata JSON Cache ====================

    def get_cached_metadata(self, ecosystem: str, package_name: str, ttl_seconds: float = 604800.0) -> Optional[Dict[str, Any]]:
        """Retrieve registry JSON metadata from disk cache if within TTL (default: 7 days)."""
        eco_dir = self.metadata_dir / ecosystem
        cache_file = eco_dir / f"{package_name}.json"
        if not cache_file.exists():
            return None

        mtime = cache_file.stat().st_mtime
        if (time.time() - mtime) > ttl_seconds:
            return None

        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            return None

    def save_cached_metadata(self, ecosystem: str, package_name: str, data: Dict[str, Any]) -> None:
        """Persist registry JSON metadata to disk cache."""
        eco_dir = self.metadata_dir / ecosystem
        cache_file = eco_dir / f"{package_name}.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(data), encoding="utf-8")

    # ==================== Payload Archive Bytes Cache ====================

    def get_cached_payload(self, ecosystem: str, package_name: str, version: str) -> Optional[bytes]:
        """Retrieve cached tarball / zip bytes for a specific package release."""
        eco_dir = self.payloads_dir / ecosystem
        cache_file = eco_dir / f"{package_name}-{version}.archive"
        if not cache_file.exists():
            return None

        try:
            return cache_file.read_bytes()
        except Exception:
            return None

    def save_cached_payload(self, ecosystem: str, package_name: str, version: str, content: bytes) -> None:
        """Persist downloaded archive bytes to disk cache."""
        eco_dir = self.payloads_dir / ecosystem
        cache_file = eco_dir / f"{package_name}-{version}.archive"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_bytes(content)

    def evict_package(self, ecosystem: str, package_name: str) -> None:
        """Evict metadata and payload archives for a specific package to force fresh network fetch."""
        meta_file = self.metadata_dir / ecosystem / f"{package_name}.json"
        meta_file.unlink(missing_ok=True)

        payload_dir = self.payloads_dir / ecosystem
        if payload_dir.exists():
            for f in payload_dir.glob(f"{package_name}-*.archive"):
                f.unlink(missing_ok=True)

    # ==================== Cache Statistics & Cleanup ====================

    def clean_payload_cache(self) -> int:
        """Purge all ephemeral payload archives to reclaim disk space immediately."""
        purged = 0
        if self.payloads_dir.exists():
            for root, _, files in os.walk(self.payloads_dir):
                for f in files:
                    try:
                        p = Path(root) / f
                        p.unlink(missing_ok=True)
                        purged += 1
                    except Exception:
                        pass
        return purged

    def clean_all_cache(self) -> int:
        """Purge all cached catalogs, metadata JSON files, and payloads."""
        purged = 0
        for d in [self.catalogs_dir, self.metadata_dir, self.payloads_dir]:
            if d.exists():
                for root, _, files in os.walk(d):
                    for f in files:
                        try:
                            p = Path(root) / f
                            p.unlink(missing_ok=True)
                            purged += 1
                        except Exception:
                            pass
        return purged

    def get_cache_stats(self) -> Dict[str, Any]:
        """Calculate total disk space used by cache directories."""
        total_size = 0
        file_count = 0
        for dirpath, _, filenames in os.walk(self.cache_root):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
                file_count += 1

        return {
            "cache_root": str(self.cache_root.resolve()),
            "total_files": file_count,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }

