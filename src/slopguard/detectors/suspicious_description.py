"""
Plugin detector: suspicious link / lure text in package metadata.

Reference implementation of the plugin pattern — a new signal added as a single
file with no changes anywhere else in the pipeline. Emits
``SUSPICIOUS_DESCRIPTION_LINK`` (see ``SIGNAL_CATALOG``). Conservative and
non-gating: it nudges the score but never on its own produces a MALICIOUS verdict.
"""

from __future__ import annotations

import re
from typing import List

from slopguard.core.signals import Finding
from slopguard.detectors.base import Detector, PackageContext, Stage, register_detector

_LURE_PATTERNS = [
    (re.compile(r"\b(?:discord\.gg|discord(?:app)?\.com/invite)/\S+", re.I), "Discord invite link"),
    (re.compile(r"\bt\.me/\S+", re.I), "Telegram link"),
    (re.compile(r"\b(?:bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|rebrand\.ly)/\S+", re.I), "URL shortener"),
    (re.compile(r"\b(?:free\s+(?:airdrop|nitro|robux|v[\-\s]?bucks)|claim\s+your\s+(?:airdrop|reward))\b", re.I),
     "Airdrop / freebie lure"),
    (re.compile(r"\bwallet\s+(?:connect|verification|validation)\b", re.I), "Wallet-drainer lure"),
]


@register_detector
class SuspiciousDescriptionDetector(Detector):
    name = "suspicious_description"
    version = "1"
    stage = Stage.METADATA
    applies_to = frozenset({"*"})

    async def analyze(self, ctx: PackageContext) -> List[Finding]:
        meta = ctx.metadata
        if meta is None:
            return []
        haystack = " ".join(
            str(x) for x in (
                meta.description,
                meta.homepage,
                *(meta.project_urls.values() if meta.project_urls else ()),
            ) if x
        )
        if not haystack.strip():
            return []

        hits = []
        for pattern, label in _LURE_PATTERNS:
            m = pattern.search(haystack)
            if m:
                hits.append((label, m.group(0)[:120]))

        if not hits:
            return []

        labels = ", ".join(sorted({h[0] for h in hits}))
        return [
            Finding.from_spec(
                "SUSPICIOUS_DESCRIPTION_LINK",
                detector=self.name,
                description=f"Package metadata contains: {labels}.",
                locations=[f"metadata -> {h[1]}" for h in hits[:3]],
                metadata={"matches": [{"label": l, "text": t} for l, t in hits[:5]]},
            )
        ]
