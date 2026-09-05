"""
Sentinel Registry Adapters.
"""

from slopguard.adapters.base import BaseRegistryAdapter
from slopguard.adapters.pypi import PyPIAdapter
from slopguard.adapters.npm import NpmAdapter
from slopguard.core.dto import Ecosystem

ADAPTER_REGISTRY = {
    Ecosystem.PYPI: PyPIAdapter,
    Ecosystem.NPM: NpmAdapter,
}

def get_adapter(ecosystem: Ecosystem) -> BaseRegistryAdapter:
    """Get the appropriate registry adapter instance for an ecosystem."""
    adapter_cls = ADAPTER_REGISTRY.get(ecosystem)
    if not adapter_cls:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")
    return adapter_cls()
