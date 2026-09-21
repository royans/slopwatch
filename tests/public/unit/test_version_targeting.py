"""Scoring a specific release (install-guard): adapters resolve that release, the scorer passes it through."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from slopwatch.adapters.npm import NpmAdapter
from slopwatch.adapters.pypi import PyPIAdapter
from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.cache import DiskCacheManager
from slopwatch.core.dto import ASTSecurityReport, Ecosystem, PackageMetadata, ThreatVerdict, WatchlistCandidate


def _fake_session_cm(responses):
    """aiohttp.ClientSession stand-in: .get(url) yields the next canned (status, json/text/bytes)."""
    class Resp:
        def __init__(self, status, body):
            self.status, self._b = status, body
        async def json(self): return self._b
        async def text(self): return self._b
        async def read(self): return self._b
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    session = MagicMock()
    session.get = MagicMock(side_effect=lambda url, **k: Resp(*responses(url)))
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, session


async def test_pypi_feed_titles_have_no_version(tmp_path):
    xml = ("<rss><channel>"
           "<item><title>vera-audit added to PyPI</title><pubDate>Sun, 20 Sep 2026 10:00:00 GMT</pubDate></item>"
           "<item><title>other 1.2.3</title></item></channel></rss>")
    cm, _ = _fake_session_cm(lambda url: (200, xml))
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=cm):
        events = await ad.fetch_recent_creations()
    assert [e.release_version for e in events] == ["latest", "1.2.3"]


async def test_pypi_specific_version_downloads_that_release(tmp_path):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    meta = PackageMetadata(ecosystem=Ecosystem.PYPI, package_name="pkg", latest_version="2.0.0",
                           tarball_url="https://files/pkg-2.0.0.tar.gz")
    fetched = []

    def responses(url):
        fetched.append(url)
        if url.endswith("/pkg/1.0.0/json"):
            return 200, {"urls": [{"packagetype": "bdist_wheel", "url": "https://files/w.whl"},
                                  {"packagetype": "sdist", "url": "https://files/pkg-1.0.0.tar.gz"}]}
        return 200, b"tarball"

    cm, _ = _fake_session_cm(responses)
    ad.inspect_package_metadata = AsyncMock(return_value=meta)
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=cm), \
         patch("slopwatch.adapters.pypi.analyze_python_package_tarball", return_value=ASTSecurityReport()) as an:
        await ad.download_and_inspect_payload("pkg", "1.0.0")
    assert fetched[-1] == "https://files/pkg-1.0.0.tar.gz"
    an.assert_called_once()


@pytest.mark.parametrize("version", [None, "latest", "2.0.0"])
async def test_pypi_latest_uses_metadata_tarball(tmp_path, version):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    meta = PackageMetadata(ecosystem=Ecosystem.PYPI, package_name="pkg", latest_version="2.0.0",
                           tarball_url="https://files/pkg-2.0.0.tar.gz")
    fetched = []
    cm, _ = _fake_session_cm(lambda url: (fetched.append(url) or 200, b"x"))
    ad.inspect_package_metadata = AsyncMock(return_value=meta)
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=cm), \
         patch("slopwatch.adapters.pypi.analyze_python_package_tarball", return_value=ASTSecurityReport()):
        await ad.download_and_inspect_payload("pkg", version)
    assert fetched == ["https://files/pkg-2.0.0.tar.gz"]


async def test_pypi_unknown_version_is_flagged_not_scored_as_latest(tmp_path):
    ad = PyPIAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    meta = PackageMetadata(ecosystem=Ecosystem.PYPI, package_name="pkg", latest_version="2.0.0",
                           tarball_url="https://files/pkg-2.0.0.tar.gz")
    cm, _ = _fake_session_cm(lambda url: (404, {}))
    ad.inspect_package_metadata = AsyncMock(return_value=meta)
    with patch("slopwatch.adapters.pypi.aiohttp.ClientSession", return_value=cm):
        report = await ad.download_and_inspect_payload("pkg", "9.9.9")
    assert report.flags == ["VERSION_NOT_FOUND"]


_PACKUMENT = {
    "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1"},
    "versions": {
        "1.0.0": {"dist": {"tarball": "https://r/pkg-1.0.0.tgz"}},
        "2.0.0": {"dist": {"tarball": "https://r/pkg-2.0.0.tgz"}},
        "3.0.0-rc.1": {"dist": {"tarball": "https://r/pkg-3.0.0-rc.1.tgz"}},
    },
}


@pytest.mark.parametrize("version,expected", [
    (None, "pkg-2.0.0.tgz"), ("latest", "pkg-2.0.0.tgz"),   # "latest" is what the inbound feed sends
    ("1.0.0", "pkg-1.0.0.tgz"), ("next", "pkg-3.0.0-rc.1.tgz"),
])
async def test_npm_resolves_the_requested_version(tmp_path, version, expected):
    ad = NpmAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    fetched = []

    def responses(url):
        fetched.append(url)
        return (200, _PACKUMENT) if "registry" in url and not url.endswith(".tgz") else (200, b"tgz")

    cm, _ = _fake_session_cm(responses)
    with patch("slopwatch.adapters.npm.aiohttp.ClientSession", return_value=cm), \
         patch("slopwatch.adapters.npm.analyze_npm_package_tarball", return_value=ASTSecurityReport()), \
         patch("slopwatch.adapters.npm.analyze_npm_package_manifest", return_value=ASTSecurityReport()):
        await ad.download_and_inspect_payload("pkg", version)
    assert fetched[-1].endswith(expected)


async def test_npm_unknown_version_is_flagged(tmp_path):
    ad = NpmAdapter(cache_manager=DiskCacheManager(cache_root=tmp_path))
    cm, _ = _fake_session_cm(lambda url: (200, _PACKUMENT))
    with patch("slopwatch.adapters.npm.aiohttp.ClientSession", return_value=cm), \
         patch("slopwatch.adapters.npm.analyze_npm_package_manifest", return_value=ASTSecurityReport()):
        report = await ad.download_and_inspect_payload("pkg", "9.9.9")
    assert "VERSION_NOT_FOUND" in report.flags


def _scorer_setup(ast):
    cand = WatchlistCandidate(ecosystem=Ecosystem.PYPI, normalized_name="some-pkg", entity_token="some",
                              capability_token="pkg", framework_token="general", risk_weight=10)
    meta = PackageMetadata(ecosystem=Ecosystem.PYPI, package_name="some-pkg", latest_version="2.0.0",
                           author="a", author_email="a@gmail.com", monthly_downloads=10)
    ad = MagicMock()
    ad.inspect_package_metadata = AsyncMock(return_value=meta)
    ad.download_and_inspect_payload = AsyncMock(return_value=ast)
    return cand, ad


async def test_scorer_passes_pinned_version_to_the_adapter():
    cand, ad = _scorer_setup(ASTSecurityReport(total_source_files=1, total_lines_of_code=10))
    with patch("slopwatch.adapters.get_adapter", return_value=ad):
        det = await ProgressiveThreatEvaluator().evaluate_candidate(cand, version="1.0.0")
    ad.download_and_inspect_payload.assert_awaited_once_with("some-pkg", "1.0.0")
    assert det.release_version == "1.0.0"
    assert det.analysis_details["scored_version"] == "1.0.0"
    assert det.analysis_details["version_metrics"]["latest_version"] == "2.0.0"


async def test_scorer_defaults_to_latest_without_a_version():
    cand, ad = _scorer_setup(ASTSecurityReport(total_source_files=1, total_lines_of_code=10))
    with patch("slopwatch.adapters.get_adapter", return_value=ad):
        det = await ProgressiveThreatEvaluator().evaluate_candidate(cand)
    ad.download_and_inspect_payload.assert_awaited_once_with("some-pkg", "2.0.0")
    assert det.release_version == "2.0.0"


async def test_scorer_reports_missing_version_without_a_verdict_about_the_package():
    cand, ad = _scorer_setup(ASTSecurityReport(flags=["VERSION_NOT_FOUND"]))
    with patch("slopwatch.adapters.get_adapter", return_value=ad):
        det = await ProgressiveThreatEvaluator().evaluate_candidate(cand, version="9.9.9")
    assert det.analysis_details["verdict_reason"] == "VERSION_NOT_FOUND"
    assert det.threat_score == 0 and det.verdict == ThreatVerdict.BENIGN_COMMUNITY
