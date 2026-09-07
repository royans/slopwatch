# Changelog

All notable changes to SlopWatch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is `0.x`, minor releases may include behavior changes to detection
logic and verdicts.

## [Unreleased]

### Added

- **`UNVERIFIED_HIGH_SIGNAL` verdict and detection-confidence framework**
  (`slopwatch.core.confidence`). YARA rules now carry a HIGH / MEDIUM / LOW
  confidence rating, fed through a Bayesian gate that separates
  confidently-confirmed `MALICIOUS` / `SUSPICIOUS` findings from real-but-
  unconfirmed signal, which now surfaces as `UNVERIFIED_HIGH_SIGNAL`.
- **Domain and vendor reputation subsystem** (`slopwatch.core.domain_trust`):
  dynamic domain-trustworthiness scoring with threat dampening, a trusted-vendor
  taxonomy with 50% score dampening and dependency-hijack detection,
  cryptographic-provenance and download-momentum facets, and materialized
  domain reputations.
- **New detections**: Windows shortcut (`.lnk`) hijacking / browser-extension
  sideload, and dangerous calls executed at module scope outside `setup.py`.
- **Contextual reachability**: install-time vs call-time classification and
  file-proximity gating for dangerous-call scoring.
- **Golden-malware recall gate**: regression suite against the live DataDog /
  OSSF malware corpus, run weekly and on demand in CI (`-m corpus`).

### Changed

- Broadened vendor / brand impersonation tables; generic brand tokens
  (e.g. a bare `google` or `aws`) are now disambiguated to cut false hits.
- Final threat score is clamped to the 0–1000 schema bound.
- Frontend build tools, `setup.py` test / publish / custom-install hooks, and
  Node preflight checks are demoted or gated to reduce false positives.
- systemd / LaunchAgent persistence is treated as low confidence; unconfirmed
  backdoor signals are excluded for established community libraries.

### Fixed

- Confidence gate no longer demotes confirmed malware.
- `SUSPICIOUS_OBFUSCATION` YARA hits now contribute to the threat score.
- A bare `mcp.json` mention is no longer flagged as credential hijacking.
- Null domain-reputation no longer crashes provenance scoring.
- Numerous false positives on popular / established packages, community
  libraries, and multi-file credential patterns.
- DB findings-table migration runs before `create_all`, preventing a duplicate
  index conflict.

## [0.1.0] — 2026-09-06

Initial public release of SlopWatch: a deterministic, zero-LLM supply-chain
security scanner for PyPI and npm packages, manifests, and lockfiles.

- Static AST inspection of `setup.py`, `pyproject.toml`, and module code.
- npm lifecycle-script analysis and unpacked-payload inspection.
- Pre-compiled YARA threat engine (73 rules).
- Manifest and lockfile auditing via `slopwatch check` auto-discovery.
- Brand-impersonation and phantom-squat detection.
- CLI: `check`, `audit`, `inspect`, `scan`, `info`, `init`.

[Unreleased]: https://github.com/royans/slopwatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/royans/slopwatch/releases/tag/v0.1.0
