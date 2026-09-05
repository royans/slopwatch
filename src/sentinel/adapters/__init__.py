"""
Sentinel Registry Adapters.
"""

from sentinel.adapters.base import BaseRegistryAdapter
from sentinel.adapters.pypi import PyPIAdapter
from sentinel.adapters.npm import NpmAdapter
from sentinel.core.dto import Ecosystem

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
