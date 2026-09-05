import pytest
from pathlib import Path
from sentinel.core.dto import Ecosystem, WatchlistCandidate, WatchlistState
from sentinel.db.engine import DatabaseManager
from sentinel.db.repository import SentinelRepository
from sentinel.linter.lockfile import DependencyLinter


@pytest.mark.asyncio
async def test_dependency_linter_requirements_txt(tmp_path: Path):
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Setup registered & watchlist packages
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, {"requests", "pydantic"})
        await repo.bulk_upsert_watchlist([
            WatchlistCandidate(
                ecosystem=Ecosystem.PYPI,
                normalized_name="fastapi-azure-b2c",
                entity_token="azure",
                capability_token="auth",
                framework_token="fastapi",
                risk_weight=90,
            )
        ])

        # Create sample requirements.txt
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\nfastapi-azure-b2c==0.1.0\n")

        linter = DependencyLinter(repo)
        result = await linter.audit_file(req_file)

        assert result["is_clean"] is False
        assert result["total_dependencies"] == 2
        assert result["flagged_count"] == 1
        assert result["flagged_dependencies"][0]["normalized"] == "fastapi-azure-b2c"
        assert result["flagged_dependencies"][0]["severity"] == "CRITICAL"

    await db.close()


@pytest.mark.asyncio
async def test_dependency_linter_poetry_lock(tmp_path: Path):
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, {"requests"})
        await repo.bulk_upsert_watchlist([
            WatchlistCandidate(
                ecosystem=Ecosystem.PYPI,
                normalized_name="flask-openai-assistant",
                entity_token="openai",
                capability_token="assistant",
                framework_token="flask",
                risk_weight=95,
            )
        ])

        poetry_lock = tmp_path / "poetry.lock"
        poetry_lock.write_text(
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
            '[[package]]\nname = "flask-openai-assistant"\nversion = "0.1.0"\n'
        )

        linter = DependencyLinter(repo)
        result = await linter.audit_file(poetry_lock)

        assert result["ecosystem"] == "pypi"
        assert result["total_dependencies"] == 2
        assert result["flagged_count"] == 1
        assert result["flagged_dependencies"][0]["normalized"] == "flask-openai-assistant"
        assert result["flagged_dependencies"][0]["severity"] == "CRITICAL"

    await db.close()


@pytest.mark.asyncio
async def test_dependency_linter_npm_package_json_and_yarn(tmp_path: Path):
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        await repo.bulk_sync_registered_packages(Ecosystem.NPM, {"react", "lodash"})
        await repo.bulk_upsert_watchlist([
            WatchlistCandidate(
                ecosystem=Ecosystem.NPM,
                normalized_name="react-stripe-checkout-v2",
                entity_token="stripe",
                capability_token="checkout",
                framework_token="react",
                risk_weight=85,
            )
        ])

        pkg_json = tmp_path / "package.json"
        pkg_json.write_text(
            '{"dependencies": {"react": "^18.2.0", "react-stripe-checkout-v2": "^0.1.0"}, "devDependencies": {"lodash": "^4.17.21"}}'
        )

        linter = DependencyLinter(repo)
        res_json = await linter.audit_file(pkg_json)
        assert res_json["ecosystem"] == "npm"
        assert res_json["total_dependencies"] == 3
        assert res_json["flagged_count"] == 1
        assert res_json["flagged_dependencies"][0]["normalized"] == "react-stripe-checkout-v2"

        yarn_lock = tmp_path / "yarn.lock"
        yarn_lock.write_text(
            'react@^18.2.0:\n  version "18.2.0"\n\n'
            'react-stripe-checkout-v2@^0.1.0:\n  version "0.1.0"\n'
        )
        res_yarn = await linter.audit_file(yarn_lock)
        assert res_yarn["ecosystem"] == "npm"
        assert res_yarn["total_dependencies"] == 2
        assert res_yarn["flagged_count"] == 1
        assert res_yarn["flagged_dependencies"][0]["normalized"] == "react-stripe-checkout-v2"

        pnpm_lock = tmp_path / "pnpm-lock.yaml"
        pnpm_lock.write_text(
            'dependencies:\n'
            '  react: 18.2.0\n'
            '  react-stripe-checkout-v2: 0.1.0\n'
        )
        res_pnpm = await linter.audit_file(pnpm_lock)
        assert res_pnpm["ecosystem"] == "npm"
        assert res_pnpm["total_dependencies"] == 2
        assert res_pnpm["flagged_count"] == 1
        assert res_pnpm["flagged_dependencies"][0]["normalized"] == "react-stripe-checkout-v2"

    await db.close()




@pytest.mark.asyncio
async def test_dependency_linter_standalone_offline_typosquat(tmp_path: Path):
    """Verify standalone mode detects brand typosquats without a database or network."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("reqeusts==2.31.0\n")

    linter = DependencyLinter(repository=None, offline=True)
    result = await linter.audit_file(req_file)

    assert result["is_clean"] is False
    assert result["total_dependencies"] == 1
    assert result["flagged_count"] == 1
    assert result["flagged_dependencies"][0]["normalized"] == "reqeusts"
    assert "SUSPICIOUS_TYPOSQUAT" in result["flagged_dependencies"][0]["reason"]


@pytest.mark.asyncio
async def test_dependency_linter_standalone_hallucinated_package(tmp_path: Path, monkeypatch):
    """Verify standalone mode flags 404 upstream packages as hallucinated dependencies."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("phantom-ai-pkg-fake==1.0.0\nvalid-pkg==1.0.0\n")

    async def mock_verify_upstream_batch(self, items, ecosystem):
        # mock return: fake returns 404, valid returns 200
        res = []
        for raw, norm, ver in items:
            status = 404 if "fake" in norm else 200
            res.append((raw, norm, ver, status))
        return res

    monkeypatch.setattr(DependencyLinter, "_verify_upstream_batch", mock_verify_upstream_batch)

    linter = DependencyLinter(repository=None, offline=False)
    result = await linter.audit_file(req_file)

    assert result["is_clean"] is False
    assert result["total_dependencies"] == 2
    assert result["flagged_count"] == 1
    assert result["flagged_dependencies"][0]["normalized"] == "phantom-ai-pkg-fake"
    assert result["flagged_dependencies"][0]["reason"] == "UNREGISTERED_OR_HALLUCINATED_PACKAGE"


@pytest.mark.asyncio
async def test_dependency_linter_direct_vcs_and_raw_url(tmp_path: Path):
    """Verify linter flags direct git+ and tarball URLs that bypass registry audits."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.31.0\n"
        "git+https://github.com/evil/repo.git#egg=evil-pkg\n"
        "https://evil.com/releases/backdoor.tar.gz\n"
    )

    linter = DependencyLinter(repository=None, offline=True)
    result = await linter.audit_file(req_file)

    assert result["is_clean"] is False
    assert result["total_dependencies"] == 3
    assert result["flagged_count"] == 2
    reasons = [item["reason"] for item in result["flagged_dependencies"]]
    assert all(r == "DIRECT_VCS_OR_RAW_URL_DEPENDENCY" for r in reasons)

    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        '{"dependencies": {"lodash": "^4.17.21", "my-fork": "git+https://github.com/org/fork.git"}}'
    )
    res_npm = await linter.audit_file(pkg_json)
    assert res_npm["is_clean"] is False
    assert res_npm["flagged_count"] == 1
    assert res_npm["flagged_dependencies"][0]["reason"] == "DIRECT_VCS_OR_RAW_URL_DEPENDENCY"


@pytest.mark.asyncio
async def test_dependency_linter_allowlist_whitelisting(tmp_path: Path):
    """Verify that allowlist permits internal packages and approved VCS links."""
    cfg_file = tmp_path / ".slopguard.yaml"
    cfg_file.write_text("""
allowlist:
  - "my-internal-company-sdk"
  - "git+https://github.com/approved/fork.git"
fail_on: "HIGH"
""")

    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.31.0\n"
        "my-internal-company-sdk==1.0.0\n"
        "git+https://github.com/approved/fork.git\n"
    )

    from sentinel.linter.lockfile import load_project_config
    cfg = load_project_config(tmp_path)
    assert "my-internal-company-sdk" in cfg["allowlist"]

    linter = DependencyLinter(repository=None, offline=True, config=cfg)
    result = await linter.audit_file(req_file)

    flagged_names = [item["package"] for item in result["flagged_dependencies"]]
    assert "my-internal-company-sdk" not in flagged_names
    assert "git+https://github.com/approved/fork.git" not in flagged_names
    assert result["is_clean"] is True
