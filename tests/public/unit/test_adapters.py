import json
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
import aiohttp
from pathlib import Path

from sentinel.adapters.pypi import PyPIAdapter
from sentinel.adapters.npm import NpmAdapter
from sentinel.core.dto import Ecosystem
from sentinel.core.cache import DiskCacheManager


def test_pypi_normalization():
    adapter = PyPIAdapter()
    assert adapter.normalize_name("FastAPI_Azure.Auth") == "fastapi-azure-auth"
    assert adapter.normalize_name("django---slack...oauth") == "django-slack-oauth"


def test_npm_normalization():
    adapter = NpmAdapter()
    assert adapter.normalize_name("  @Auth/Azure-Jwt  ") == "@auth/azure-jwt"
    assert adapter.normalize_name("Express-Session") == "express-session"


@pytest.mark.asyncio
async def test_pypi_inspect_metadata_mocked(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = PyPIAdapter(cache_manager=cache)

    mock_pypi_json = {
        "info": {
            "name": "django-slack-oauth",
            "version": "1.5.0",
            "author": "Sergey Keller",
            "author_email": "izdieu@gmail.com",
            "summary": "Django OAuth backend for Slack",
        },
        "urls": [
            {
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/django-slack-oauth-1.5.0.tar.gz",
                "upload_time_iso_8601": "2026-08-20T10:00:00Z",
            }
        ],
        "releases": {},
    }

    mock_stats_json = {
        "data": {
            "last_day": 12,
            "last_week": 85,
            "last_month": 450,
        }
    }

    class MockResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    def mock_get(url, **kwargs):
        if "pypistats.org" in url:
            return MockResponse(200, mock_stats_json)
        return MockResponse(200, mock_pypi_json)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        meta = await adapter.inspect_package_metadata("django-slack-oauth")
        assert meta is not None
        assert meta.package_name == "django-slack-oauth"
        assert meta.latest_version == "1.5.0"
        assert meta.monthly_downloads == 450
        assert meta.weekly_downloads == 85
        assert meta.daily_downloads == 12


@pytest.mark.asyncio
async def test_npm_inspect_metadata_mocked(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = NpmAdapter(cache_manager=cache)

    mock_npm_json = {
        "name": "@auth/azure-jwt",
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "2.0.0": {
                "name": "@auth/azure-jwt",
                "version": "2.0.0",
                "author": {"name": "Auth Dev", "email": "dev@auth.org"},
                "description": "Azure JWT helper for Auth.js",
                "dist": {"unpackedSize": 5120, "fileCount": 4},
            }
        },
    }

    mock_stats_json = {
        "downloads": 12000,
        "package": "@auth/azure-jwt",
    }

    class MockResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    def mock_get(url, **kwargs):
        if "api.npmjs.org" in url:
            return MockResponse(200, mock_stats_json)
        return MockResponse(200, mock_npm_json)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        meta = await adapter.inspect_package_metadata("@auth/azure-jwt")
        assert meta is not None
        assert meta.package_name == "@auth/azure-jwt"
        assert meta.latest_version == "2.0.0"
        assert meta.monthly_downloads == 12000
        assert meta.weekly_downloads == 3000


@pytest.mark.asyncio
async def test_npm_fetch_full_catalog_paginates_beyond_default_page(tmp_path: Path):
    """
    Regression test: the npm replica caps an unparameterized _all_docs request at a
    small default page (observed: 1,000 rows out of ~4.3M total in production) — the
    adapter must paginate via startkey/skip until the full catalog is retrieved,
    not silently return just the first page.
    """
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = NpmAdapter(cache_manager=cache, catalog_page_size=3)

    # Simulate a 7-package catalog split across pages of size 3, including a
    # _design/ doc that must be skipped but still advance the cursor. `startkey`
    # is INCLUSIVE on the real server (no `skip` support), so each continuation
    # page's first row duplicates the previous page's last row.
    all_ids = ["a-pkg", "b-pkg", "_design/lib", "c-pkg", "d-pkg", "e-pkg", "f-pkg"]

    class MockResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    call_count = {"n": 0}

    def mock_get(url, **kwargs):
        call_count["n"] += 1
        params = kwargs.get("params", {})
        assert "skip" not in params, "this replica returns HTTP 400 for skip+startkey"
        page_size = int(params["limit"])
        start_idx = 0
        if "startkey" in params:
            start_key = json.loads(params["startkey"])
            start_idx = all_ids.index(start_key)  # inclusive: re-includes the boundary row
        page = all_ids[start_idx:start_idx + page_size]
        return MockResponse(200, {"rows": [{"id": pkg_id} for pkg_id in page]})

    with patch("aiohttp.ClientSession.get", side_effect=mock_get):
        names = await adapter.fetch_full_catalog()

    assert names == {"a-pkg", "b-pkg", "c-pkg", "d-pkg", "e-pkg", "f-pkg"}  # _design/ excluded
    assert call_count["n"] >= 3  # multiple pages needed to exhaust 7 rows at page_size=3


@pytest.mark.asyncio
async def test_pypi_inspect_legacy_metadata_serial_resolution_mocked(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = PyPIAdapter(cache_manager=cache)

    mock_pypi_json = {
        "info": {
            "name": "google-calendar-helper",
            "version": "0.3",
            "author": "Sergio Gabriel Teves",
            "author_email": "gabriel.sgt@gmail.com",
            "summary": "Helper for Google Calendar API",
        },
        "urls": [],
        "releases": {"0.3": []},
        "last_serial": 100555,
    }

    class MockGetResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    class MockPostResponse:
        def __init__(self, status, body_bytes):
            self.status = status
            self._body = body_bytes

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def read(self):
            return self._body

    # XML-RPC response with timestamp 1240353135 (2009-04-21T22:32:15Z)
    import xmlrpc.client
    mock_xml_body = xmlrpc.client.dumps(
        ([["google-calendar-helper", "0.3", 1240353135, "new release", 100555]],),
        methodresponse=True,
    ).encode("utf-8")

    def mock_get(url, **kwargs):
        return MockGetResponse(200, mock_pypi_json)

    def mock_post(url, **kwargs):
        return MockPostResponse(200, mock_xml_body)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get), patch(
        "aiohttp.ClientSession.post", side_effect=mock_post
    ):
        meta = await adapter.inspect_package_metadata("google-calendar-helper")
        assert meta is not None
        assert meta.package_name == "google-calendar-helper"
        assert meta.latest_version == "0.3"
        assert meta.first_published_at == datetime(2009, 4, 21, 22, 32, 15, tzinfo=timezone.utc)
        assert meta.latest_release_at == datetime(2009, 4, 21, 22, 32, 15, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_pypi_inspect_legacy_metadata_serial_threshold_fallback(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = PyPIAdapter(cache_manager=cache)

    mock_pypi_json = {
        "info": {
            "name": "legacy-no-files-pkg",
            "version": "1.0",
            "author": "Legacy Author",
            "summary": "Old package without files",
        },
        "urls": [],
        "releases": {"1.0": []},
        "last_serial": 500000,
    }

    class MockGetResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    class MockPostResponse:
        def __init__(self, status, body_bytes):
            self.status = status
            self._body = body_bytes

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def read(self):
            return self._body

    # XML-RPC response returns empty list
    import xmlrpc.client
    mock_xml_body = xmlrpc.client.dumps(([],), methodresponse=True).encode("utf-8")

    def mock_get(url, **kwargs):
        return MockGetResponse(200, mock_pypi_json)

    def mock_post(url, **kwargs):
        return MockPostResponse(200, mock_xml_body)

    with patch("aiohttp.ClientSession.get", side_effect=mock_get), patch(
        "aiohttp.ClientSession.post", side_effect=mock_post
    ):
        meta = await adapter.inspect_package_metadata("legacy-no-files-pkg")
        assert meta is not None
        assert meta.first_published_at == datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_npm_inspect_metadata_extracts_deprecation(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = NpmAdapter(cache_manager=cache)

    mock_npm_json = {
        "dist-tags": {"latest": "1.3.1"},
        "versions": {
            "1.3.1": {
                "name": "gemini-web",
                "version": "1.3.1",
                "deprecated": "This version is no longer support.",
                "dist": {"tarball": "https://registry.npmjs.org/gemini-web/-/gemini-web-1.3.1.tgz"},
                "author": {"name": "linzhizhao", "email": "linzhizhao@example.com"},
            }
        },
        "time": {
            "created": "2017-03-10T00:00:00.000Z",
            "1.3.1": "2017-03-10T00:00:00.000Z",
        },
    }

    class MockGetResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    with patch("aiohttp.ClientSession.get", return_value=MockGetResponse(200, mock_npm_json)):
        meta = await adapter.inspect_package_metadata("gemini-web")
        assert meta is not None
        assert meta.is_deprecated is True
        assert meta.deprecation_reason == "This version is no longer support."


@pytest.mark.asyncio
async def test_pypi_inspect_metadata_extracts_yanked_and_inactive(tmp_path: Path):
    cache = DiskCacheManager(cache_root=tmp_path / "cache")
    adapter = PyPIAdapter(cache_manager=cache)

    mock_pypi_yanked = {
        "info": {
            "name": "old-yanked-lib",
            "version": "0.5.0",
            "yanked": True,
            "yanked_reason": "Security issue in v0.5.0",
            "classifiers": ["Development Status :: 7 - Inactive"],
        },
        "urls": [],
        "releases": {},
    }

    class MockGetResponse:
        def __init__(self, status, json_data):
            self.status = status
            self._json = json_data

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def json(self):
            return self._json

    with patch("aiohttp.ClientSession.get", return_value=MockGetResponse(200, mock_pypi_yanked)):
        meta = await adapter.inspect_package_metadata("old-yanked-lib")
        assert meta is not None
        assert meta.is_deprecated is True
        assert meta.deprecation_reason == "Security issue in v0.5.0"
