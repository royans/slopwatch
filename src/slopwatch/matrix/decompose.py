"""
Reverse-map a package name onto the ``{framework}-{entity}-{capability}``
slopsquat naming template.

This mirrors how the FlagThis crawler assigns grammar tokens to an inbound
package (``flagthis_sentinel.scheduler.worker``): find a known brand / entity
token in the name, treat it as the *entity*, and fill the framework and
capability slots positionally. It is **stateless** — it needs only the brand
tables that already ship — so ``slopwatch inspect`` can surface
"this name matches an AI-hallucination naming template targeting <brand>" and,
when the entity is a real brand, whether the publisher is affiliated with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from slopwatch.core.brands import PRIORITY_BRAND_WEIGHTS, compute_brand_priority
from slopwatch.core.dto import Ecosystem
from slopwatch.core.normalizers import extract_clean_email_and_domain
from slopwatch.core.taxonomies import VENDOR_DOMAINS

# Brand tokens that are also ordinary English / dev vocabulary. For these we
# only claim a template match when the token *leads* the name (the classic
# impersonation position, e.g. `safe-utils`), not when it appears anywhere
# (`my-safe-config` should not read as "names the brand SAFE").
_AMBIGUOUS_BRAND_TOKENS = {
    "base", "safe", "together", "circle", "phantom", "rainbow", "argent",
    "modal", "fal", "flow", "mint", "near", "sui", "aptos", "grok", "sol",
    "eth", "btc", "hf", "matic",
}


@dataclass(frozen=True)
class NameDecomposition:
    entity: str
    capability: str
    framework: str
    template: str  # e.g. "python-tether-fastcrest"
    is_high_value_brand: bool
    brand_weight: int


def _normalize(name: str) -> str:
    n = name.lower().strip().replace("_", "-")
    if n.startswith("@") and "/" in n:
        n = n.split("/", 1)[1]
    return n.replace("/", "-")


def decompose_package_name(name: str, ecosystem: Ecosystem) -> Optional[NameDecomposition]:
    """Return the naming-template decomposition when a known brand / entity
    token appears in ``name``, else ``None``."""
    norm = _normalize(name)
    match = compute_brand_priority(norm)
    if not match:
        return None
    entity, weight = match

    toks = [t for t in norm.split("-") if t]
    if not toks:
        return None

    if entity in _AMBIGUOUS_BRAND_TOKENS and toks[0] != entity and toks[-1] != entity:
        return None

    default_fw = "node" if ecosystem == Ecosystem.NPM else "python"

    if len(toks) == 1:
        cap, fw = "core", default_fw
    elif len(toks) == 2:
        cap = toks[1] if entity == toks[0] else toks[0]
        fw = default_fw
    else:
        fw = toks[0] if toks[0] != entity else default_fw
        remaining = [t for t in toks if t not in (entity, fw)]
        cap = remaining[0] if remaining else "core"

    return NameDecomposition(
        entity=entity,
        capability=cap,
        framework=fw,
        template=f"{fw}-{entity}-{cap}",
        is_high_value_brand=entity in PRIORITY_BRAND_WEIGHTS,
        brand_weight=weight,
    )


def publisher_matches_brand(entity: str, author_email: Optional[str]) -> Optional[bool]:
    """Whether the publisher's email domain belongs to the brand ``entity``.

    ``None`` when the brand has no known vendor domain to check against (so the
    caller should stay silent rather than imply a negative).
    """
    domains = VENDOR_DOMAINS.get(entity.lower())
    if not domains:
        return None
    if not author_email:
        return False
    _, domain = extract_clean_email_and_domain(author_email)
    if not domain:
        return False
    return any(domain == d or domain.endswith(f".{d}") for d in domains)
