import pytest

from slopwatch.core.dto import Ecosystem
from slopwatch.matrix.decompose import decompose_package_name, publisher_matches_brand


@pytest.mark.parametrize(
    "name,template,brand",
    [
        ("fastcrest-tether", "python-tether-fastcrest", "tether"),
        ("stripe-python-sdk", "python-stripe-sdk", "stripe"),
        ("openai-agents-sdk", "python-openai-agents", "openai"),
        ("c8kv-azure-utils", "c8kv-azure-utils", "azure"),
    ],
)
def test_decompose_brand_anchored(name, template, brand):
    d = decompose_package_name(name, Ecosystem.PYPI)
    assert d is not None
    assert d.entity == brand
    assert d.template == template
    assert d.is_high_value_brand is True


@pytest.mark.parametrize("name", ["requests", "pytest-cov", "my-safe-config", "numpy"])
def test_decompose_no_brand_token_returns_none(name):
    assert decompose_package_name(name, Ecosystem.PYPI) is None


def test_ambiguous_token_only_counts_when_leading_or_trailing():
    # "safe" is ambiguous vocabulary — leading position counts, buried does not
    assert decompose_package_name("safe-utils", Ecosystem.PYPI) is not None
    assert decompose_package_name("my-safe-config", Ecosystem.PYPI) is None


def test_publisher_matches_brand():
    assert publisher_matches_brand("stripe", "dev@stripe.com") is True
    assert publisher_matches_brand("stripe", "attacker@gmail.com") is False
    assert publisher_matches_brand("stripe", None) is False
    # a brand with no known vendor domain -> cannot judge
    assert publisher_matches_brand("fastcrest", "x@example.com") is None


def test_npm_scope_stripped():
    d = decompose_package_name("@evil/stripe-checkout", Ecosystem.NPM)
    assert d is not None
    assert d.entity == "stripe"
    assert d.framework == "node"
