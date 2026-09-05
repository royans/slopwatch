"""
FlagThis Sentinel PyPI Registry Adapter.

Provides streaming catalog ingestion, real-time RSS feed parsing,
JSON metadata retrieval, and tarball AST security analysis for Python/PyPI,
with integrated local disk caching for minimal bandwidth consumption.
"""

import re
import asyncio
import xmlrpc.client
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Set, List, Optional
import aiohttp

from sentinel.adapters.base import BaseRegistryAdapter
from sentinel.core.dto import (
    Ecosystem,
    PackageCreationEvent,
    PackageMetadata,
    ASTSecurityReport,
)
from sentinel.core.cache import DiskCacheManager
from sentinel.assessor.python_ast import analyze_python_package_tarball


class PyPIAdapter(BaseRegistryAdapter):
    def __init__(
        self,
        simple_index_url: str = "https://pypi.org/simple/",
        rss_url: str = "https://pypi.org/rss/packages.xml",
        json_api_base: str = "https://pypi.org/pypi",
        timeout_seconds: float = 30.0,
        cache_manager: Optional[DiskCacheManager] = None,
    ):
        self.simple_index_url = simple_index_url
        self.rss_url = rss_url
        self.json_api_base = json_api_base
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.cache = cache_manager or DiskCacheManager()

    @property
    def ecosystem(self) -> Ecosystem:
        return Ecosystem.PYPI

    def normalize_name(self, raw_name: str) -> str:
        """PEP 503 normalization: lowercase and collapse [-_.]+ to a single hyphen."""
        return re.sub(r"[-_.]+", "-", raw_name).lower()

    async def fetch_full_catalog(self) -> Set[str]:
        """Stream PyPI simple index and extract all normalized package names, using disk cache when fresh."""
        # 1. Check disk cache first (24h TTL)
        cached = self.cache.get_cached_catalog("pypi", ttl_seconds=86400.0)
        if cached:
            return cached

        package_names: Set[str] = set()
        headers = {"Accept": "application/vnd.pypi.simple.v1+json"}

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            try:
                # Try JSON simple index first
                async with session.get(self.simple_index_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        projects = data.get("projects", [])
                        for p in projects:
                            name = p.get("name")
                            if name:
                                package_names.add(self.normalize_name(name))
                        if package_names:
                            self.cache.save_cached_catalog("pypi", package_names)
                            return package_names
            except Exception:
                pass

            # Fallback to HTML simple index
            async with session.get(self.simple_index_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    matches = re.findall(r'<a href="[^"]*">([^<]+)</a>', text)
                    for name in matches:
                        package_names.add(self.normalize_name(name))

        if package_names:
            self.cache.save_cached_catalog("pypi", package_names)

        return package_names

    async def fetch_recent_creations(self, limit: int = 50) -> List[PackageCreationEvent]:
        """Fetch and parse newly created packages from PyPI RSS feed."""
        events: List[PackageCreationEvent] = []

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(self.rss_url) as resp:
                if resp.status != 200:
                    return events

                xml_text = await resp.text()
                try:
                    root = ET.fromstring(xml_text)
                    channel = root.find("channel")
                    if channel is None:
                        return events

                    for item in channel.findall("item")[:limit]:
                        title = item.findtext("title") or ""
                        pub_date_str = item.findtext("pubDate") or ""

                        parts = title.strip().split()
                        if not parts:
                            continue
                        raw_pkg = parts[0]
                        version = parts[1] if len(parts) > 1 else "0.1.0"

                        pub_date = datetime.now(timezone.utc)
                        if pub_date_str:
                            try:
                                from email.utils import parsedate_to_datetime
                                pub_date = parsedate_to_datetime(pub_date_str)
                            except Exception:
                                pass

                        events.append(
                            PackageCreationEvent(
                                ecosystem=Ecosystem.PYPI,
                                package_name=self.normalize_name(raw_pkg),
                                published_at=pub_date,
                                release_version=version,
                            )
                        )
                except Exception:
                    pass

        return events

    async def fetch_download_stats(self, session: aiohttp.ClientSession, package_name: str) -> tuple[int, int, int]:
        """Fetch real-world download counts (monthly, weekly, daily) from PyPI Stats API with rate-limit backoff."""
        stats_url = f"https://pypistats.org/api/packages/{package_name}/recent"
        headers = {"User-Agent": "FlagThisSentinel/1.0 (security-research@flagthis.com)"}
        
        for attempt in range(3):
            try:
                async with session.get(stats_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5.0)) as stat_resp:
                    if stat_resp.status == 200:
                        stat_data = await stat_resp.json()
                        recent = stat_data.get("data", {})
                        d = int(recent.get("last_day", 0) or 0)
                        w = int(recent.get("last_week", 0) or 0)
                        m = int(recent.get("last_month", 0) or 0)
                        return m, w, d
                    elif stat_resp.status == 429:
                        # Rate limited by pypistats.org: exponential backoff
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    else:
                        break
            except Exception:
                await asyncio.sleep(0.5)
        return 0, 0, 0

    async def fetch_timestamp_from_serial(
        self, session: aiohttp.ClientSession, package_name: str, serial: Optional[int]
    ) -> Optional[datetime]:
        """
        Query PyPI changelog XML-RPC API asynchronously for packages lacking uploaded files
        (e.g., historical packages from 2005-2015 where tarballs were hosted externally).
        """
        if not serial or serial <= 0:
            return None

        xml_req = xmlrpc.client.dumps((max(1, serial - 1),), "changelog_since_serial")
        headers = {
            "Content-Type": "text/xml",
            "User-Agent": "FlagThisSentinel/1.0 (security-research@flagthis.com)",
        }
        try:
            # PyPI XML-RPC endpoint is hosted at https://pypi.org/pypi
            async with session.post(
                self.json_api_base,
                data=xml_req,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=8.0),
            ) as resp:
                if resp.status == 200:
                    resp_bytes = await resp.read()
                    params, _ = xmlrpc.client.loads(resp_bytes)
                    events = params[0] if params else []
                    norm_target = self.normalize_name(package_name)
                    for ev in events:
                        # ev format: [name, version, timestamp, action, serial]
                        if len(ev) >= 3 and self.normalize_name(str(ev[0])) == norm_target:
                            ts = ev[2]
                            if isinstance(ts, int) and ts > 0:
                                return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass
        return None

    async def inspect_package_metadata(self, package_name: str) -> Optional[PackageMetadata]:
        """Query PyPI JSON API for package release metadata, using local cache when available."""
        norm_name = self.normalize_name(package_name)

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Check local cache first (7-day TTL), but ensure it contains valid historical first_published_at
            cached_data = self.cache.get_cached_metadata("pypi", norm_name, ttl_seconds=604800.0)
            if cached_data and cached_data.get("first_published_at"):
                # If cached record has 0 downloads, refresh from PyPI Stats API
                if cached_data.get("monthly_downloads", 0) == 0:
                    m, w, d = await self.fetch_download_stats(session, norm_name)
                    if m > 0 or w > 0 or d > 0:
                        cached_data["monthly_downloads"] = m
                        cached_data["weekly_downloads"] = w
                        cached_data["daily_downloads"] = d
                        self.cache.save_cached_metadata("pypi", norm_name, cached_data)
                return PackageMetadata(**cached_data)

            url = f"{self.json_api_base}/{norm_name}/json"

            async with session.get(url) as resp:
                if resp.status != 200:
                    return None

                data = await resp.json()
                info = data.get("info", {})
                urls = data.get("urls", [])

                tarball_url = None
                for u in urls:
                    if u.get("packagetype") == "sdist":
                        tarball_url = u.get("url")
                        break
                if not tarball_url and urls:
                    tarball_url = urls[0].get("url")

                version = info.get("version", "0.1.0")

                # Extract earliest and latest release upload timestamps
                all_upload_times: List[datetime] = []
                releases = data.get("releases", {})
                for ver_tag, files in releases.items():
                    for f in files:
                        ut = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if ut:
                            try:
                                if ut.endswith("Z"):
                                    ut = ut.replace("Z", "+00:00")
                                dt = datetime.fromisoformat(ut)
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=timezone.utc)
                                all_upload_times.append(dt)
                            except Exception:
                                pass

                for u in urls:
                    ut = u.get("upload_time_iso_8601") or u.get("upload_time")
                    if ut:
                        try:
                            if ut.endswith("Z"):
                                ut = ut.replace("Z", "+00:00")
                            dt = datetime.fromisoformat(ut)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            all_upload_times.append(dt)
                        except Exception:
                            pass

                first_pub: Optional[datetime] = None
                latest_rel: Optional[datetime] = None

                if all_upload_times:
                    first_pub = min(all_upload_times)
                    latest_rel = max(all_upload_times)
                else:
                    # Attempt to resolve exact historical timestamp via PyPI changelog serial
                    last_serial = data.get("last_serial")
                    if last_serial:
                        exact_dt = await self.fetch_timestamp_from_serial(session, norm_name, last_serial)
                        if exact_dt:
                            first_pub = exact_dt
                            latest_rel = exact_dt

                    # If serial is low (< 20,000,000), it is a pre-2023 pre-AI wave legacy package
                    if not first_pub and last_serial and last_serial < 20_000_000:
                        first_pub = datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
                        latest_rel = datetime(2015, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

                if not first_pub:
                    first_pub = datetime.now(timezone.utc)
                if not latest_rel:
                    latest_rel = datetime.now(timezone.utc)

                # Calculate SemVer release burst velocity
                release_count = len(releases) if releases else 1
                has_rapid_semver_burst = False
                if len(all_upload_times) >= 3:
                    sorted_times = sorted(all_upload_times)
                    if (sorted_times[2] - sorted_times[0]).total_seconds() < 86400:
                        has_rapid_semver_burst = True

                # Fetch real download stats from PyPI Stats API
                monthly_downloads, weekly_downloads, daily_downloads = await self.fetch_download_stats(session, norm_name)

                raw_author = info.get("author") or info.get("maintainer")
                raw_email = info.get("author_email") or info.get("maintainer_email")
                from sentinel.core.normalizers import normalize_email_address
                clean_email = normalize_email_address(raw_email)

                # Check PyPI deprecation & yanked status
                is_yanked = bool(info.get("yanked", False))
                yanked_reason = info.get("yanked_reason")
                classifiers = info.get("classifiers", []) or []
                is_inactive = any("Development Status :: 7 - Inactive" in str(c) for c in classifiers)
                is_deprecated = is_yanked or is_inactive
                deprecation_reason = None
                if is_yanked and yanked_reason:
                    deprecation_reason = str(yanked_reason).strip()
                elif is_yanked:
                    deprecation_reason = "Release yanked on PyPI"
                elif is_inactive:
                    deprecation_reason = "Development Status :: 7 - Inactive"

                meta = PackageMetadata(
                    ecosystem=Ecosystem.PYPI,
                    package_name=norm_name,
                    latest_version=version,
                    author=raw_author,
                    author_email=clean_email,
                    homepage=info.get("home_page") or info.get("project_url"),
                    project_urls=info.get("project_urls") or {},
                    description=info.get("summary"),
                    tarball_url=tarball_url,
                    published_at=latest_rel,
                    first_published_at=first_pub,
                    latest_release_at=latest_rel,
                    release_count=release_count,
                    has_rapid_semver_burst=has_rapid_semver_burst,
                    monthly_downloads=monthly_downloads,
                    weekly_downloads=weekly_downloads,
                    daily_downloads=daily_downloads,
                    is_deprecated=is_deprecated,
                    deprecation_reason=deprecation_reason,
                )

                self.cache.save_cached_metadata("pypi", norm_name, meta.model_dump(mode="json"))
                return meta


    async def download_and_inspect_payload(self, package_name: str, version: Optional[str] = None) -> ASTSecurityReport:
        """Download PyPI tarball and perform static AST analysis in-memory with zero disk clutter."""
        meta = await self.inspect_package_metadata(package_name)
        if not meta or not meta.tarball_url:
            return ASTSecurityReport(
                flags=["METADATA_UNAVAILABLE_OR_NO_SDIST"],
                composite_threat_score=30,
            )

        pkg_version = version or meta.latest_version

        # 1. Check local archive cache if present
        cached_bytes = self.cache.get_cached_payload("pypi", package_name, pkg_version)
        if cached_bytes:
            return analyze_python_package_tarball(cached_bytes, package_name)

        # 2. Download from PyPI into memory buffer (ephemeral bytes analyzed via io.BytesIO)
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(meta.tarball_url) as resp:
                if resp.status != 200:
                    return ASTSecurityReport(
                        flags=["TARBALL_DOWNLOAD_FAILED"],
                        composite_threat_score=40,
                    )

                tarball_bytes = await resp.read()
                return analyze_python_package_tarball(tarball_bytes, package_name)

