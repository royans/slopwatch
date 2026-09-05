import pytest
from pathlib import Path
from slopguard.core.cache import DiskCacheManager


def test_disk_cache_catalog(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path)

    # 1. Miss initially
    assert cache.get_cached_catalog("pypi") is None

    # 2. Save
    names = {"requests", "fastapi", "flask"}
    cache.save_cached_catalog("pypi", names)

    # 3. Hit
    cached = cache.get_cached_catalog("pypi")
    assert cached == names


def test_disk_cache_metadata(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path)

    assert cache.get_cached_metadata("pypi", "fastapi") is None

    meta = {"package_name": "fastapi", "version": "0.100.0"}
    cache.save_cached_metadata("pypi", "fastapi", meta)

    cached = cache.get_cached_metadata("pypi", "fastapi")
    assert cached == meta


def test_disk_cache_payload(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path)

    assert cache.get_cached_payload("pypi", "fastapi", "0.100.0") is None

    payload = b"FAKE_TARBALL_BYTES_12345"
    cache.save_cached_payload("pypi", "fastapi", "0.100.0", payload)

    cached = cache.get_cached_payload("pypi", "fastapi", "0.100.0")
    assert cached == payload

    stats = cache.get_cache_stats()
    assert stats["total_files"] >= 1


def test_disk_cache_cleanup(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path)

    # Populate catalogs, metadata, and payloads
    cache.save_cached_catalog("pypi", {"pkg1", "pkg2"})
    cache.save_cached_metadata("pypi", "pkg1", {"ver": "1.0"})
    cache.save_cached_payload("pypi", "pkg1", "1.0", b"FAKE_PAYLOAD_BYTES")

    stats_before = cache.get_cache_stats()
    assert stats_before["total_files"] == 3

    # Clean only payloads
    purged_payloads = cache.clean_payload_cache()
    assert purged_payloads == 1
    assert cache.get_cached_payload("pypi", "pkg1", "1.0") is None
    assert cache.get_cached_metadata("pypi", "pkg1") is not None

    # Clean all
    purged_all = cache.clean_all_cache()
    assert purged_all == 2
    stats_after = cache.get_cache_stats()
    assert stats_after["total_files"] == 0

