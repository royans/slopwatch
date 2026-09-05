import pytest
from slopguard.core.dto import Ecosystem
from slopguard.matrix.generator import generate_ecosystem_candidates, filter_unregistered_candidates


def test_generate_pypi_candidates():
    candidates = generate_ecosystem_candidates(
        ecosystem=Ecosystem.PYPI,
        entities=["snowflake", "azure"],
        capabilities=["auth", "jwt"],
        custom_frameworks=["fastapi"],
    )
    assert len(candidates) > 0
    names = [c.normalized_name for c in candidates]
    assert "fastapi-azure-auth" in names or "azure-fastapi-auth" in names
    assert all(c.ecosystem == Ecosystem.PYPI for c in candidates)


def test_filter_unregistered_candidates():
    candidates = generate_ecosystem_candidates(
        ecosystem=Ecosystem.PYPI,
        entities=["supabase"],
        capabilities=["auth"],
        custom_frameworks=["fastapi"],
    )
    registered = {"fastapi-supabase-auth"}
    unregistered = filter_unregistered_candidates(candidates, registered)

    unregistered_names = [c.normalized_name for c in unregistered]
    assert "fastapi-supabase-auth" not in unregistered_names
    assert len(unregistered) < len(candidates)


def test_pypi_pep503_normalization_prevents_duplicate_candidates():
    candidates = generate_ecosystem_candidates(
        ecosystem=Ecosystem.PYPI,
        entities=["supabase"],
        capabilities=["auth"],
        custom_frameworks=["fastapi"],
    )
    names = [c.normalized_name for c in candidates]
    # All PyPI candidates must be strictly PEP 503 normalized (no underscores)
    assert not any("_" in n for n in names)
    # Exactly 3 permutation patterns generated, not 6 (duplicates between - and _ collapsed)
    assert len(candidates) == 3
    registered = {"fastapi-supabase-auth"}
    unregistered = filter_unregistered_candidates(candidates, registered)
    unregistered_names = [c.normalized_name for c in unregistered]
    assert "fastapi-supabase-auth" not in unregistered_names
    assert "fastapi_supabase_auth" not in unregistered_names
    assert len(unregistered) == 2

