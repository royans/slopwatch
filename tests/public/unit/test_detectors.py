"""Tests for the detector plugin framework (auto-discovery + engine)."""

import pytest

from sentinel.core.dto import Ecosystem, PackageMetadata, WatchlistCandidate
from sentinel.core.signals import Finding
from sentinel.detectors import (
    DetectionEngine,
    Detector,
    PackageContext,
    Stage,
    load_all_detectors,
    register_detector,
    registered_detector_names,
)


def _meta(**kw):
    base = dict(ecosystem=Ecosystem.NPM, package_name="p", latest_version="1.0.0")
    base.update(kw)
    return PackageMetadata(**base)


def test_builtin_detector_is_auto_discovered():
    names = registered_detector_names()
    assert "suspicious_description" in names


def test_load_all_detectors_instantiates_registered():
    dets = load_all_detectors()
    assert any(d.name == "suspicious_description" for d in dets)
    # disabled list is honoured
    dets2 = load_all_detectors(disabled=["suspicious_description"])
    assert not any(d.name == "suspicious_description" for d in dets2)


@pytest.mark.asyncio
async def test_suspicious_description_detector_flags_lure_text():
    from sentinel.detectors.suspicious_description import SuspiciousDescriptionDetector

    det = SuspiciousDescriptionDetector()
    ctx = PackageContext(
        ecosystem=Ecosystem.NPM, package_name="p",
        metadata=_meta(description="Install and then join our discord.gg/abc123 for the free airdrop!"),
    )
    findings = await det.analyze(ctx)
    assert len(findings) == 1
    assert findings[0].code == "SUSPICIOUS_DESCRIPTION_LINK"
    assert findings[0].gates_malicious is False


@pytest.mark.asyncio
async def test_suspicious_description_detector_quiet_on_clean_metadata():
    from sentinel.detectors.suspicious_description import SuspiciousDescriptionDetector

    det = SuspiciousDescriptionDetector()
    ctx = PackageContext(
        ecosystem=Ecosystem.NPM, package_name="p",
        metadata=_meta(description="A well-behaved HTTP client library with retries and timeouts."),
    )
    assert await det.analyze(ctx) == []


@pytest.mark.asyncio
async def test_engine_isolates_a_broken_detector():
    class GoodDetector(Detector):
        name = "t_good"
        stage = Stage.NAME_ONLY

        async def analyze(self, ctx):
            return [Finding.from_spec("SIGNAL_HIGH_VALUE_BRAND_TARGET", detector=self.name)]

    class BrokenDetector(Detector):
        name = "t_broken"
        stage = Stage.NAME_ONLY

        async def analyze(self, ctx):
            raise RuntimeError("boom")

    engine = DetectionEngine(detectors=[GoodDetector(), BrokenDetector()])
    ctx = PackageContext(ecosystem=Ecosystem.PYPI, package_name="x")
    findings = await engine.run(ctx)
    assert [f.code for f in findings] == ["SIGNAL_HIGH_VALUE_BRAND_TARGET"]
    assert findings[0].detector == "t_good"


@pytest.mark.asyncio
async def test_engine_respects_stage_and_ecosystem_gating():
    class NeedsPayload(Detector):
        name = "t_payload"
        stage = Stage.PAYLOAD
        applies_to = frozenset({"npm"})

        async def analyze(self, ctx):
            return [Finding.from_spec("SIGNAL_EMPTY_CODE_STUB", detector=self.name)]

    engine = DetectionEngine(detectors=[NeedsPayload()])

    # wrong ecosystem
    assert await engine.run(PackageContext(ecosystem=Ecosystem.PYPI, package_name="x", ast_report=None)) == []
    # right ecosystem but no payload available
    assert await engine.run(PackageContext(ecosystem=Ecosystem.NPM, package_name="x")) == []


@pytest.mark.asyncio
async def test_register_detector_rejects_non_detector():
    with pytest.raises(TypeError):
        register_detector(object)  # type: ignore[arg-type]
