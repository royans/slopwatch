"""
Sentinel npm Registry Adapter.

Provides streaming catalog ingestion, CouchDB changes feed parsing,
registry metadata retrieval, and package.json lifecycle script analysis for npm/Node.js,
with integrated local disk caching for minimal bandwidth consumption.
"""

import json
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
from sentinel.assessor.npm_manifest import analyze_npm_package_manifest
from sentinel.assessor.npm_source import analyze_npm_package_tarball, merge_ast_reports


NPM_CATALOG_PAGE_SIZE = 10000
# Safety cap on pagination loops: 2000 pages * 10k rows/page = 20M, well beyond
# npm's real catalog size (~4.3M at time of writing). Prevents a runaway loop if
# the upstream ever stops advancing the cursor.
NPM_CATALOG_MAX_PAGES = 2000


class NpmAdapter(BaseRegistryAdapter):
    def __init__(
        self,
        all_docs_url: str = "https://replicate.npmjs.com/_all_docs",
        changes_url: str = "https://replicate.npmjs.com/_changes",
        registry_base: str = "https://registry.npmjs.org",
        timeout_seconds: float = 30.0,
        cache_manager: Optional[DiskCacheManager] = None,
        catalog_page_size: int = NPM_CATALOG_PAGE_SIZE,
    ):
        self.all_docs_url = all_docs_url
        self.changes_url = changes_url
        self.registry_base = registry_base
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.cache = cache_manager or DiskCacheManager()
        self.catalog_page_size = catalog_page_size

    @property
    def ecosystem(self) -> Ecosystem:
        return Ecosystem.NPM

    def normalize_name(self, raw_name: str) -> str:
        """npm package normalization: lowercase and trim whitespace."""
        return raw_name.strip().lower()

    async def fetch_full_catalog(self) -> Set[str]:
        """
        Stream npm _all_docs and extract all package names, using disk cache when fresh.

        The replica caps an unparameterized request at a small default page (observed:
        1,000 rows returned out of ~4.3M total_rows) — this paginates via CouchDB's
        startkey/skip cursor until the full catalog has been retrieved.
        """
        cached = self.cache.get_cached_catalog("npm", ttl_seconds=86400.0)
        if cached:
            return cached

        package_names: Set[str] = set()
        last_key: Optional[str] = None

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for _ in range(NPM_CATALOG_MAX_PAGES):
                params = {"limit": str(self.catalog_page_size)}
                if last_key is not None:
                    params["startkey"] = json.dumps(last_key)

                async with session.get(self.all_docs_url, params=params) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json()

                raw_rows = data.get("rows", [])
                if not raw_rows:
                    break

                rows = raw_rows
                if last_key is not None and rows[0].get("id") == last_key:
                    # startkey is INCLUSIVE, so the previous page's last doc reappears
                    # as this page's first row — drop it to avoid reprocessing.
                    # (`skip=1` would sidestep this cleanly, but this replica returns
                    # HTTP 400 for any request combining startkey with skip.)
                    rows = rows[1:]

                for r in rows:
                    name = r.get("id")
                    if not name:
                        continue
                    last_key = name
                    if not name.startswith("_design/"):
                        package_names.add(self.normalize_name(name))

                if len(raw_rows) < self.catalog_page_size:
                    break  # short page (pre-dedup count): this was the last one

        if package_names:
            self.cache.save_cached_catalog("npm", package_names)

        return package_names

    async def fetch_recent_creations(self, limit: int = 50) -> List[PackageCreationEvent]:
        """Fetch recently modified/created packages from npm CouchDB changes feed."""
        events: List[PackageCreationEvent] = []
        url = f"{self.changes_url}?descending=true&limit={limit}"

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return events

                data = await resp.json()
                results = data.get("results", [])
                for r in results:
                    name = r.get("id")
                    if name and not name.startswith("_design/"):
                        events.append(
                            PackageCreationEvent(
                                ecosystem=Ecosystem.NPM,
                                package_name=self.normalize_name(name),
                                published_at=datetime.now(timezone.utc),
                                release_version="latest",
                            )
                        )

        return events

    async def inspect_package_metadata(self, package_name: str) -> Optional[PackageMetadata]:
        """Query npm registry JSON API for package metadata, using local cache when available."""
        norm_name = self.normalize_name(package_name)

        cached_data = self.cache.get_cached_metadata("npm", norm_name, ttl_seconds=604800.0)
        if cached_data:
            return PackageMetadata(**cached_data)

        encoded_name = norm_name.replace("/", "%2F") if "/" in norm_name else norm_name
        url = f"{self.registry_base}/{encoded_name}"

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None

                data = await resp.json()
                dist_tags = data.get("dist-tags", {})
                latest_ver = dist_tags.get("latest", "0.1.0")
                versions = data.get("versions", {})
                ver_data = versions.get(latest_ver, {})

                dist = ver_data.get("dist", {})
                tarball_url = dist.get("tarball")

                author = ver_data.get("author", {})
                author_name = None
                author_email = None
                from sentinel.core.normalizers import normalize_email_address
                if isinstance(author, dict):
                    author_name = author.get("name")
                    author_email = normalize_email_address(author.get("email"))
                elif isinstance(author, str):
                    author_email = normalize_email_address(author)
                    author_name = author.split("<")[0].strip() if "<" in author else author

                # Fetch download stats from npm API
                monthly_downloads = 0
                weekly_downloads = 0
                try:
                    stats_url = f"https://api.npmjs.org/downloads/point/last-month/{encoded_name}"
                    async with session.get(stats_url, timeout=aiohttp.ClientTimeout(total=5.0)) as stat_resp:
                        if stat_resp.status == 200:
                            stat_data = await stat_resp.json()
                            monthly_downloads = int(stat_data.get("downloads", 0) or 0)
                            weekly_downloads = max(0, monthly_downloads // 4)
                except Exception:
                    pass

                # Extract release upload times from npm time mapping
                time_map = data.get("time", {})
                all_npm_times = []
                for k, v in time_map.items():
                    if k not in ("created", "modified") and isinstance(v, str):
                        try:
                            if v.endswith("Z"):
                                v = v.replace("Z", "+00:00")
                            dt = datetime.fromisoformat(v)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            all_npm_times.append(dt)
                        except Exception:
                            pass

                created_str = time_map.get("created")
                first_pub = None
                if created_str:
                    try:
                        if created_str.endswith("Z"):
                            created_str = created_str.replace("Z", "+00:00")
                        first_pub = datetime.fromisoformat(created_str)
                        if first_pub.tzinfo is None:
                            first_pub = first_pub.replace(tzinfo=timezone.utc)
                    except Exception:
                        pass

                if not first_pub and all_npm_times:
                    first_pub = min(all_npm_times)

                latest_rel = max(all_npm_times) if all_npm_times else datetime.now(timezone.utc)
                if not first_pub:
                    first_pub = latest_rel

                # Check deprecation status (latest version, package-level, or all versions)
                latest_deprecated = ver_data.get("deprecated")
                top_deprecated = data.get("deprecated")
                all_deprecated = bool(versions) and all(
                    isinstance(v, dict) and bool(v.get("deprecated")) for v in versions.values()
                )
                is_deprecated = bool(latest_deprecated or top_deprecated or all_deprecated)
                deprecation_reason = None
                if latest_deprecated:
                    deprecation_reason = str(latest_deprecated).strip()
                elif top_deprecated:
                    deprecation_reason = str(top_deprecated).strip()
                elif all_deprecated:
                    for v in versions.values():
                        if isinstance(v, dict) and v.get("deprecated"):
                            deprecation_reason = str(v.get("deprecated")).strip()
                            break
                    if not deprecation_reason:
                        deprecation_reason = "All versions deprecated"

                meta = PackageMetadata(
                    ecosystem=Ecosystem.NPM,
                    package_name=norm_name,
                    latest_version=latest_ver,
                    author=author_name,
                    author_email=author_email,
                    homepage=ver_data.get("homepage"),
                    description=ver_data.get("description"),
                    tarball_url=tarball_url,
                    published_at=latest_rel,
                    first_published_at=first_pub,
                    latest_release_at=latest_rel,
                    release_count=len(versions) if versions else 1,
                    monthly_downloads=monthly_downloads,
                    weekly_downloads=weekly_downloads,
                    daily_downloads=max(0, weekly_downloads // 7),
                    is_deprecated=is_deprecated,
                    deprecation_reason=deprecation_reason,
                )

                self.cache.save_cached_metadata("npm", norm_name, meta.model_dump(mode="json"))
                return meta

    async def download_and_inspect_payload(self, package_name: str, version: Optional[str] = None) -> ASTSecurityReport:
        """
        Fetch package manifest (lifecycle scripts, declared metadata) AND the actual
        tarball source (real JS/TS content), merging both reports. Previously this
        only ever inspected package.json — never the real payload, so a malicious
        package could hide its logic in index.js (executed at require()-time, or
        merely referenced by an innocuous-looking lifecycle script) with zero chance
        of detection. See sentinel.assessor.npm_source for the source scanner.
        """
        norm_name = self.normalize_name(package_name)
        encoded_name = norm_name.replace("/", "%2F") if "/" in norm_name else norm_name
        url = f"{self.registry_base}/{encoded_name}"

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return ASTSecurityReport(
                        flags=["NPM_METADATA_UNAVAILABLE"],
                        composite_threat_score=30,
                    )

                data = await resp.json()
                manifest_report = analyze_npm_package_manifest(data, norm_name)

                dist_tags = data.get("dist-tags", {})
                latest_ver = version or dist_tags.get("latest", "0.1.0")
                versions = data.get("versions", {})
                ver_data = versions.get(latest_ver, data)
                tarball_url = ver_data.get("dist", {}).get("tarball")
                if not tarball_url:
                    return manifest_report

                cached_bytes = self.cache.get_cached_payload("npm", norm_name, latest_ver)
                if cached_bytes:
                    tarball_bytes = cached_bytes
                else:
                    async with session.get(tarball_url) as tresp:
                        if tresp.status != 200:
                            return manifest_report
                        tarball_bytes = await tresp.read()
                    self.cache.save_cached_payload("npm", norm_name, latest_ver, tarball_bytes)

                source_report = analyze_npm_package_tarball(tarball_bytes, norm_name)
                return merge_ast_reports(manifest_report, source_report)
