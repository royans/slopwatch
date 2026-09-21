"""Cursor-based readers of the npm _changes stream and PyPI's event log."""
import xmlrpc.client
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from slopwatch.adapters.npm import NpmAdapter
from slopwatch.adapters.pypi import PyPIAdapter
from slopwatch.core.cache import DiskCacheManager


def _session(handler):
    class Resp:
        def __init__(self, status, body):
            self.status, self._b = status, body
        async def json(self, **k): return self._b
        async def read(self): return self._b
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
    s = MagicMock()
    s.get = MagicMock(side_effect=lambda url, **k: Resp(*handler(url)))
    s.post = MagicMock(side_effect=lambda url, **k: Resp(*handler(k.get("data"))))
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=s)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


async def test_npm_changes_are_grouped_and_new_packages_detected(tmp_path):
    ad = NpmAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    seen = []
    body = {"last_seq": 110, "results": [
        {"seq": 101, "id": "brand-new", "changes": [{"rev": "1-abc"}]},
        {"seq": 102, "id": "Old-Pkg", "changes": [{"rev": "88-x"}]},
        {"seq": 105, "id": "old-pkg", "changes": [{"rev": "89-y"}]},
        {"seq": 106, "id": "_design/x", "changes": [{"rev": "1-z"}]},
        {"seq": 107, "id": "gone", "changes": [{"rev": "5-q"}], "deleted": True},
    ]}
    with patch("slopwatch.adapters.npm.aiohttp.ClientSession", return_value=_session(lambda u: (seen.append(u) or 200, body))):
        page = await ad.fetch_changes_since("100", limit=2000)
    assert "since=100" in seen[0] and "limit=2000" in seen[0] and "descending" not in seen[0]
    by = {c.name: c for c in page.changes}
    assert set(by) == {"brand-new", "old-pkg", "gone"}             # design docs dropped, names normalised, merged
    assert by["brand-new"].is_new and not by["old-pkg"].is_new
    assert (by["old-pkg"].first_seq, by["old-pkg"].last_seq) == (102, 105)
    assert by["gone"].deleted
    assert page.last_seq == "110" and page.raw_count == 5


async def test_npm_tip_and_http_errors(tmp_path):
    ad = NpmAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    with patch("slopwatch.adapters.npm.aiohttp.ClientSession", return_value=_session(lambda u: (200, {"last_seq": 999, "results": []}))):
        assert await ad.fetch_changes_tip() == "999"
    with patch("slopwatch.adapters.npm.aiohttp.ClientSession", return_value=_session(lambda u: (503, {}))):
        with pytest.raises(RuntimeError):
            await ad.fetch_changes_since("1")


def _rpc(events):
    return xmlrpc.client.dumps((events,), methodresponse=True, allow_none=True).encode()


async def test_pypi_event_log_groups_projects_and_versions(tmp_path):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    events = [
        ["Fresh_Pkg", None, 1789900000, "create", 10],
        ["Fresh_Pkg", "0.1.0", 1789900001, "new release", 11],
        ["fresh-pkg", "0.1.0", 1789900002, "add source file fresh_pkg-0.1.0.tar.gz", 12],
        ["old-pkg", "2.0.0", 1789900003, "new release", 13],
        ["old-pkg", "2.0.1", 1789900004, "new release", 14],
        ["files-only", "1.0", 1789900005, "add py3 file files_only-1.0-py3-none-any.whl", 15],
        ["dead", None, 1789900006, "remove project", 16],
    ]
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=_session(lambda d: (200, _rpc(events)))):
        page = await ad.fetch_changes_since("9")
    by = {c.name: c for c in page.changes}
    assert by["fresh-pkg"].is_new and by["fresh-pkg"].version == "0.1.0" and by["fresh-pkg"].created_at is not None
    assert not by["old-pkg"].is_new and by["old-pkg"].is_release and by["old-pkg"].version == "2.0.1"
    assert not by["files-only"].is_release            # only extra files: not an update worth reviewing
    assert by["dead"].deleted
    assert page.last_seq == "16" and page.raw_count == 7


async def test_pypi_event_log_is_capped_and_resumes_at_the_last_consumed_serial(tmp_path):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    events = [[f"p{i}", "1", 1789900000 + i, "new release", 100 + i] for i in range(10)]
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=_session(lambda d: (200, _rpc(events)))):
        page = await ad.fetch_changes_since("99", limit=4)
    assert len(page.changes) == 4 and page.last_seq == "103" and page.raw_count == 4


async def test_pypi_tip(tmp_path):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    body = xmlrpc.client.dumps((41275191,), methodresponse=True).encode()
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=_session(lambda d: (200, body))):
        assert await ad.fetch_changes_tip() == "41275191"
