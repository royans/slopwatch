import pytest
import json
from pathlib import Path
from sentinel.core.dto import Ecosystem, ThreatVerdict, SquatDetection
from sentinel.db.engine import DatabaseManager
from sentinel.db.repository import SentinelRepository
from sentinel.exporter.dossier import DossierExporter


@pytest.mark.asyncio
async def test_dossier_exporter_skips_benign_community(tmp_path: Path):
    """
    BENIGN_COMMUNITY detections carry no security signal and shouldn't get a public
    dossier, search-index entry, or author-index inclusion. A stale dossier from a
    prior export (e.g. before this filtering existed, or before a re-audit downgraded
    the verdict) must also be cleaned up rather than left orphaned on disk.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        benign = SquatDetection(
            ecosystem=Ecosystem.PYPI,
            package_name="unrelated-benign-lib",
            author_username="dev",
            release_version="1.0.0",
            threat_score=5,
            analysis_details={"author_email": "dev@example.com", "flags": []},
            verdict=ThreatVerdict.BENIGN_COMMUNITY,
        )
        suspicious = SquatDetection(
            ecosystem=Ecosystem.PYPI,
            package_name="fastapi-azure-b2c",
            author_username="anon",
            release_version="0.1.0",
            threat_score=80,
            analysis_details={"author_email": "attacker@evilcorp.com", "flags": []},
            verdict=ThreatVerdict.SUSPICIOUS,
        )
        await repo.record_detection(benign)
        await repo.record_detection(suspicious)

        # Simulate a stale dossier left over from before this filtering existed.
        stale_dir = tmp_path / "dossiers" / "pypi"
        stale_dir.mkdir(parents=True)
        stale_dossier = stale_dir / "unrelated-benign-lib.md"
        stale_dossier.write_text("stale content", encoding="utf-8")

        exporter = DossierExporter(repo, output_dir=tmp_path)
        stats = await exporter.export_all()

        assert stats["total_dossiers_generated"] == 1  # only the suspicious one
        assert stats["skipped_benign_count"] == 1
        assert stats["cleaned_stale_dossiers_count"] == 1
        assert not stale_dossier.exists()  # cleaned up

        assert (tmp_path / "dossiers" / "pypi" / "fastapi-azure-b2c.md").exists()

        index_data = json.loads((tmp_path / "search" / "package_search_index.json").read_text())
        names_in_index = {r["name"] for r in index_data}
        assert "fastapi-azure-b2c" in names_in_index
        assert "unrelated-benign-lib" not in names_in_index

    await db.close()


@pytest.mark.asyncio
async def test_dossier_exporter_search_index_alias_is_symlink_not_duplicate(tmp_path: Path):
    """
    all_packages_index.json must be a symlink alias to package_search_index.json,
    not a second full copy — both were previously written with byte-identical
    content on every export, doubling storage for no benefit.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        detection = SquatDetection(
            ecosystem=Ecosystem.PYPI,
            package_name="fastapi-azure-b2c",
            threat_score=80,
            analysis_details={"author_email": "attacker@evilcorp.com"},
            verdict=ThreatVerdict.SUSPICIOUS,
        )
        await repo.record_detection(detection)

        exporter = DossierExporter(repo, output_dir=tmp_path)
        await exporter.export_all()

        primary = tmp_path / "search" / "package_search_index.json"
        alias = tmp_path / "search" / "all_packages_index.json"
        assert primary.exists()
        assert alias.is_symlink()
        assert alias.read_text(encoding="utf-8") == primary.read_text(encoding="utf-8")

    await db.close()


@pytest.mark.asyncio
async def test_dossier_exporter_handles_scoped_npm_packages(tmp_path: Path):
    """
    Regression test: a scoped npm package name (e.g. "@scope/name") contains a '/'
    which implies a dossier subdirectory ("dossiers/npm/@scope/name.md") that doesn't
    exist by default — export_all() must create it, not raise FileNotFoundError.
    (Surfaced in production once the real npm catalog — which is dominated by scoped
    packages — was synced for the first time.)
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        detection = SquatDetection(
            ecosystem=Ecosystem.NPM,
            package_name="@infinitebrahmanuniverse/nolb-discord-1",
            author_username="dev",
            release_version="1.0.0",
            threat_score=40,
            analysis_details={"author_email": "dev@example.com", "flags": []},
            verdict=ThreatVerdict.SUSPICIOUS,
        )
        await repo.record_detection(detection)

        exporter = DossierExporter(repo, output_dir=tmp_path)
        stats = await exporter.export_all()  # must not raise FileNotFoundError

        assert stats["total_dossiers_generated"] == 1
        dossier_file = tmp_path / "dossiers" / "npm" / "@infinitebrahmanuniverse" / "nolb-discord-1.md"
        assert dossier_file.exists()
        assert "nolb-discord-1" in dossier_file.read_text(encoding="utf-8")

    await db.close()


@pytest.mark.asyncio
async def test_dossier_exporter(tmp_path: Path):
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Add sample detection
        detection = SquatDetection(
            ecosystem=Ecosystem.PYPI,
            package_name="fastapi-azure-b2c",
            author_username="anon_hacker",
            release_version="0.1.0",
            threat_score=95,
            analysis_details={
                "author_email": "attacker@evilcorp.com",
                "flags": ["socket.connect found in setup.py:14"],
                "line_details": ["setup.py:14 -> socket.connect()"],
            },
            verdict=ThreatVerdict.MALICIOUS,
        )
        await repo.record_detection(detection)

        exporter = DossierExporter(repo, output_dir=tmp_path)
        stats = await exporter.export_all()

        assert stats["total_dossiers_generated"] == 1
        assert stats["unified_search_entries"] == 1
        assert stats["pypi_search_entries"] == 1
        assert stats["npm_search_entries"] == 0

        # Check dossier file exists
        dossier_file = tmp_path / "dossiers" / "pypi" / "fastapi-azure-b2c.md"
        assert dossier_file.exists()
        content = dossier_file.read_text(encoding="utf-8")
        assert "slug: slopsquat-pypi-fastapi-azure-b2c" in content
        assert "threat_score: 95" in content
        assert "https://pypi.org/project/fastapi-azure-b2c/" in content
        assert "created_at: " in content
        assert "updated_at: " in content

        # Check search index
        search_file = tmp_path / "search" / "package_search_index.json"
        assert search_file.exists()
        search_data = json.loads(search_file.read_text(encoding="utf-8"))
        assert len(search_data) == 1
        rec = search_data[0]
        assert rec["name"] == "fastapi-azure-b2c"
        assert rec["score"] == 95
        assert rec["upstream_url"] == "https://pypi.org/project/fastapi-azure-b2c/"
        assert "created_at" in rec
        assert "updated_at" in rec
        assert len(rec["created_at"]) == 20  # YYYY-MM-DDTHH:MM:SSZ
        assert rec["created_at"].endswith("Z")
        assert rec["updated_at"].endswith("Z")

        initial_created_at = rec["created_at"]
        initial_updated_at = rec["updated_at"]

        # Check author email & domain reverse indexes
        emails_file = tmp_path / "search" / "author_emails_index.json"
        domains_file = tmp_path / "search" / "author_domains_index.json"
        summary_file = tmp_path / "search" / "authors_summary.json"

        assert emails_file.exists()
        assert domains_file.exists()
        assert summary_file.exists()

        emails_data = json.loads(emails_file.read_text(encoding="utf-8"))
        domains_data = json.loads(domains_file.read_text(encoding="utf-8"))
        summary_data = json.loads(summary_file.read_text(encoding="utf-8"))

        assert len(emails_data) >= 1
        assert len(domains_data) >= 1
        assert summary_data["total_unique_emails"] >= 1
        assert summary_data["total_unique_domains"] >= 1

        email_entry = emails_data[0]
        assert "total_packages_count" in email_entry
        assert "questionable_packages_count" in email_entry
        assert "recency_metrics" in email_entry
        assert "published_last_1_day" in email_entry["recency_metrics"]
        assert "published_last_1_week" in email_entry["recency_metrics"]
        assert "published_last_1_month" in email_entry["recency_metrics"]
        assert "published_last_1_year" in email_entry["recency_metrics"]
        assert "is_outlier" in email_entry

        domain_entry = domains_data[0]
        assert "total_packages_count" in domain_entry
        assert "author_email_domain" in domain_entry

    await db.close()


@pytest.mark.asyncio
async def test_dossier_exporter_skips_deprecated_packages(tmp_path: Path):
    """
    Packages officially deprecated/yanked by upstream registry carry no active
    security signal and should be skipped from export, and any stale dossier cleaned up.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        detection = SquatDetection(
            ecosystem=Ecosystem.NPM,
            package_name="gemini-web",
            threat_score=35,
            is_deprecated=True,
            deprecation_reason="This version is no longer support.",
            analysis_details={"is_deprecated": True, "deprecation_reason": "This version is no longer support."},
            verdict=ThreatVerdict.SUSPICIOUS,
        )
        await repo.record_detection(detection)

        # Pre-create a stale dossier file
        stale_dossier = tmp_path / "dossiers" / "npm" / "gemini-web.md"
        stale_dossier.parent.mkdir(parents=True, exist_ok=True)
        stale_dossier.write_text("old stale dossier content")

        exporter = DossierExporter(repo, output_dir=tmp_path)
        stats = await exporter.export_all()

        assert stats["skipped_benign_count"] >= 1
        assert stats["total_dossiers_generated"] == 0
        assert not stale_dossier.exists()  # Stale dossier was cleaned up

    await db.close()


