# Changelog

All notable changes to SlopWatch are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is `0.x`, minor releases may include behavior changes to detection
logic and verdicts.

## [Unreleased]

### Added

- **Stable finding codes** (`slopwatch.core.finding_catalog`): every finding the
  manifest gate (`check` / `audit`) can raise now carries a stable `SLOP-XXXX`
  identifier, shown in the `check` table and in `--json`, and catalogued in
  `docs/FINDINGS.md`. Codes never change meaning or get reused.
- **Finding-code suppression** — `check --ignore SLOP-0003` (repeatable; accepts
  a code or a full reason string) and an `ignore:` list in `.slopwatch.yaml` /
  `[tool.slopwatch]`. Demotes a finding from build-breaking to advisory, giving
  a per-finding answer to the open "should `UNVERIFIED_HIGH_SIGNAL` fail CI?"
  question instead of a global policy change.
- **Suppression ledger**: allowlisted and ignored findings are no longer
  silently dropped — every run lists what was suppressed and why (a
  "Suppressions" table in text output, `suppressions` in `--json`). `allowlist`
  entries may now be a mapping carrying a `reason:` justification that is echoed
  in the ledger.
- **`check --stats`**: prints manifests audited, dependencies scanned, live
  registry calls, and wall time (also under `stats` in `--json`).
- **Naming-template detection in `inspect`** (`slopwatch.matrix.decompose`):
  when a package name is anchored on a known high-value brand token, `inspect`
  shows the `{framework}-{entity}-{capability}` template it fits (e.g.
  `fastcrest-tether` → `python-tether-fastcrest`, names brand `TETHER`) and
  whether the publisher's `author_email` domain is an official account for that
  brand. Stateless — uses the shipped brand tables. Suppressed for
  hugely-adopted or provenance-signed packages to avoid crying wolf on
  first-party packages like `langchain-community`. New `--json` fields:
  `naming_template`, `naming_brand`, `publisher_affiliated_with_brand`.
- **`init` writes `AGENTS.md`**: a pre-dependency `slopwatch check` rule for
  autonomous coding agents — created if absent, appended if the file already
  exists and does not mention SlopWatch.
- **Self-scan CI workflow** (`.github/workflows/self-scan.yml`) and README
  badge: SlopWatch audits its own dependency supply chain on every push and PR,
  as a credibility signal and a heuristic-regression canary.
- **`python -m slopwatch`** now works as an alias for the `slopwatch` console
  script — handy when a `pip install --user` puts the script somewhere off
  `PATH` (e.g. `~/.local/bin`).

### Changed

- **Slimmer install.** Core runtime dependencies dropped from 10 to 6
  (`aiohttp`, `pydantic`, `pyyaml`, `rich`, `click`, `yara-python`) — a fresh
  `pip install slopwatch` now pulls ~13 packages instead of ~22, and
  `yara-python` is the only remaining compiled dependency. The local SQLite
  watchlist cache moves behind a `db` extra (see Removed).
- **`slopwatch inspect` output is a short summary by default.** Instead of
  printing every flagged file:line (hundreds of lines on a large package), it
  shows a package-facts block (author, homepage, days since publish, month/week
  downloads + usage tier, codebase size + tier, provenance, registry link,
  naming template) and a severity-ranked **grouped count** of findings by
  category. The verdict panel prints **last** so it's on screen without
  scrolling. `--details` / `-d` lists every location; `--json` gains `homepage`,
  `days_since_publish`, `weekly_downloads`, `total_lines_of_code`,
  `code_size_tier`, `registry_url`, and the naming-template fields above.
- **README**: sharpened the scope statement — SlopWatch's subject is the
  dependency supply chain (package names, lockfiles, upstream archives), not the
  user's own source tree; added an explicit "not a code-quality / AI-slop
  linter" boundary.

### Fixed

- **`inspect` no longer shows a misleading "Publisher Domain … (Unindexed / New
  domain)" line.** The standalone CLI ships no author-domain reputation index, so
  every domain read as "new" — and the field is self-asserted registry metadata
  an impersonator can set to any value (`cisco.com`, `google.com`). The row is
  hidden until the reputation-snapshot feature lands; `--json`
  `domain_trust_score` is now `null` (not `0.0`) when there is no index. Build
  provenance and download count — which are registry-verified — still show.

### Removed

- **`aiodns` and `dnspython`** as dependencies — neither was imported anywhere
  in the package. Removing `aiodns` also drops the transitive `pycares` / `cffi`
  / `pycparser` C-FFI chain. `aiohttp` falls back to its threaded resolver.
- **`sqlalchemy[asyncio]` and `aiosqlite`** from the base install — the local
  SQLite watchlist / registered-package cache used by `slopwatch check` is now
  behind a `db` extra: `pip install "slopwatch[db]"`. The standalone CLI
  (`check`, `inspect`, `scan`, `audit`, `info`, `init`) runs fully without it;
  `check` prints a one-line hint if it finds a DB but the extra is missing.

## [0.2.0] — 2026-09-06

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

[Unreleased]: https://github.com/royans/slopwatch/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/royans/slopwatch/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/royans/slopwatch/releases/tag/v0.1.0
