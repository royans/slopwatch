"""
FlagThis Sentinel Composable Cartesian Matrix Generator.

Generates the multi-ecosystem long-tail candidate space across Entities,
Capabilities, and Frameworks, and computes the high-risk unregistered watchlist.
"""

from typing import List, Set, Dict
from sentinel.core.dto import Ecosystem, WatchlistState, WatchlistCandidate
from sentinel.core.taxonomies import ENTITIES, CAPABILITIES, FRAMEWORKS, DELIMITERS

# High-priority weights for critical frameworks and capabilities
HIGH_PRIORITY_CAPABILITIES = {"auth", "sso", "jwt", "oauth2", "login", "iam", "vectorstore", "embeddings", "client", "sdk"}
HIGH_PRIORITY_FRAMEWORKS = {"fastapi", "react", "next", "pydantic", "django", "express", "langchain"}


def generate_ecosystem_candidates(
    ecosystem: Ecosystem,
    entities: List[str] = ENTITIES,
    capabilities: List[str] = CAPABILITIES,
    custom_frameworks: List[str] = None,
    limit: int = 500000,
) -> List[WatchlistCandidate]:
    """
    Generate the Cartesian space of composable long-tail candidate package names
    for an ecosystem.
    """
    frameworks = custom_frameworks or FRAMEWORKS.get(ecosystem.value, [])
    delimiters = DELIMITERS.get(ecosystem.value, ["-"])
    candidates: List[WatchlistCandidate] = []
    seen_names: Set[str] = set()

    # Iterate through combinations in priority order across all entities
    for cap in capabilities:
        for fw in frameworks:
            for delim in delimiters:
                for ent in entities:
                    # Pattern 1: {fw}{delim}{ent}{delim}{cap}
                    name1 = f"{fw}{delim}{ent}{delim}{cap}".lower()
                    # Pattern 2: {ent}{delim}{fw}{delim}{cap}
                    name2 = f"{ent}{delim}{fw}{delim}{cap}".lower()
                    # Pattern 3: {ent}{delim}{cap}{delim}{fw}
                    name3 = f"{ent}{delim}{cap}{delim}{fw}".lower()

                    for n in [name1, name2, name3]:
                        # Handle npm scoped variants if delim is '/'
                        if ecosystem == Ecosystem.NPM and delim == "/":
                            n = f"@{ent}/{cap}-{fw}".lower()
                        elif ecosystem == Ecosystem.PYPI:
                            import re
                            n = re.sub(r"[-_.]+", "-", n).lower()

                        if n not in seen_names:
                            seen_names.add(n)

                            weight = 50
                            if cap in HIGH_PRIORITY_CAPABILITIES:
                                weight += 25
                            if fw in HIGH_PRIORITY_FRAMEWORKS:
                                weight += 25

                            candidates.append(
                                WatchlistCandidate(
                                    ecosystem=ecosystem,
                                    normalized_name=n,
                                    entity_token=ent,
                                    capability_token=cap,
                                    framework_token=fw,
                                    risk_weight=min(100, weight),
                                    state=WatchlistState.WATCHING,
                                )
                            )

                            if len(candidates) >= limit:
                                return candidates


    return candidates


def filter_unregistered_candidates(
    generated_candidates: List[WatchlistCandidate],
    registered_names_set: Set[str],
) -> List[WatchlistCandidate]:
    """
    Perform O(1) in-memory set-difference against the registered package catalog.
    Returns only genuine UNREGISTERED candidate targets.
    """
    unregistered: List[WatchlistCandidate] = []
    for c in generated_candidates:
        if c.normalized_name not in registered_names_set:
            unregistered.append(c)
    return unregistered
