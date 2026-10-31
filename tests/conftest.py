"""Keep the suite offline: detectors that call out to the network answer "inconclusive"
unless a test patches in its own responses."""

import pytest


@pytest.fixture(autouse=True)
def _offline_network_detectors(monkeypatch):
    from slopwatch.detectors import repo_claim

    async def _no_network(session, url):
        return 0, ""

    monkeypatch.setattr(repo_claim, "_fetch", _no_network)
    try:
        from slopwatch.detectors import maintainer_domain
    except ImportError:
        pass
    else:
        async def _unknown(session, domain):
            return None

        monkeypatch.setattr(maintainer_domain, "_domain_exists", _unknown)
    yield
