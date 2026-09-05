# 🛡️ Sentinel (Project SpectreCatch)

**Zero-LLM Multi-Ecosystem Package Squatting & Slopsquatting Detection Engine**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Test Suite](https://img.shields.io/badge/tests-247%2F247%20passing-brightgreen.svg)]()

Sentinel is an open-source, high-throughput, zero-LLM threat intelligence and package squatting detection engine for **PyPI (Python)** and **npm (Node.js)** ecosystems.

It identifies and tracks **"Slopsquatting"**—a supply-chain threat where attackers register packages named after AI-hallucinated library combinations (e.g. `fastapi-azure-auth`, `react-supabase-jwt`) to deliver malicious installation hooks when developers or AI coding assistants suggest them.

---

## ✨ Key Features

1. **Deterministic Cartesian Matrix Generator**:
   - Computes long-tail candidate spaces across **500+ tech entities**, **60+ functional capabilities**, and major frameworks.
   - Evaluates in-memory $O(1)$ set-differences against live package registries in $< 50\text{ ms}$.
2. **Inbound Feed Real-Time Tripwire & Universal Stream Scanning**:
   - Inverts active polling by monitoring PyPI RSS (`packages.xml`) and npm CouchDB streams (`_changes`).
   - Scans **all new incoming package releases** directly for security threats, weaponized hooks, and credential harvesting without requiring prior keyword presence, while preserving grammar matching for historical catalog backfills.
3. **Multi-Suite YARA Static Threat Engine & Composite Heuristics**:
   - Compiles **70 YARA rules** spanning **9 specialized detection suites** (`execution.yar`, `exfiltration.yar`, `credentials.yar`, `evasion.yar`, `obfuscation.yar`, `persistence.yar`, `supply_chain.yar`, `worm_droppers.yar`, indexed via `index.yar`).
   - Deep in-memory regex and byte-pattern static analysis across unpacked Python (`.py`) and Node.js (`.js`, `.ts`) tarballs.
   - Advanced composite threat heuristics:
     - `SOURCE_CODE_PERSISTENT_BACKDOOR`: Detects systemd units, cron tasks, launchd daemons, and registry run keys.
     - `SOURCE_CODE_EVASIVE_PAYLOAD`: Flags anti-analysis execution delays, debugger detection, and VM/sandbox evasions.
     - `SIGNAL_INFOSTEALER_SIGNATURE_MATCH`: Threat score +85 for confirmed weaponized infostealer signatures.
4. **Progressive Multi-Tier Malware Assessor**:
   - **Tier 1**: In-memory naming grammar, pre-AI temporal project classification, and package age filters.
   - **Tier 2**: Official vendor author domain verification (`@microsoft.com`, `@stripe.com`, `@okta.com`) and upstream registry deprecation detection (npm `deprecated` status and PyPI `yanked` / `Development Status :: 7 - Inactive`).
   - **Tier 3**: Deep static AST, manifest, and YARA analyzers distinguishing install-time execution from normal runtime code:
     - **Python**: Static inspection of `setup.py` and `pyproject.toml` PEP 517/518 build backends for socket connections, subprocess spawns, obfuscated base64 execution, environment variable harvesting (`os.environ`, `os.getenv`), and install hooks.
     - **npm**: Dual-layer inspection covering both declared `package.json` lifecycle scripts (`preinstall`, `install`, `postinstall`) and real tarball JavaScript/TypeScript source code (`eval`, `new Function`, `child_process`, `process.env` harvesting, and 300-char proximity dynamic code loader detection).
   - **Tier 4**: Composite multi-factor Threat Scoring (0–1000) strictly gating `MALICIOUS` verdicts to confirmed dangerous code execution, demoting deprecated/abandoned packages, and filtering them from active threat feeds.
5. **Deploy-Time Code Execution Intelligence & Indexing**:
   - Exposes structured, indexed boolean flags (`has_install_hook`, `has_network_socket`) with SQLite covering indexes (`idx_detection_install_hook`) and downstream schema generated columns to isolate packages capable of running arbitrary code at install time.
6. **Continuous Multi-Tier Priority Crawler & Freshness Engine**:
   - Prioritizes brand-new inbound releases (Tier 1), enterprise brand targets like Google, Azure, AWS, and Okta (Tier 2), and due freshness re-checks (Tier 3).
   - Grammar-scoped historical backfill (Tier 4) matching candidate token combinations to eliminate full-catalog crawl bloat.
   - Enforces an authoritative **Daily Review Rule** via `daily_review_log` (atomically capping reviews to 1 per package per UTC day).
   - Dynamically re-audits packages using an **exponential half-life freshness policy** (10 days for new releases, 50% lifespan for packages $>20$ days old, capped at 30 days).
7. **Dependency & Version Confusion Anomaly Engine**:
   - Detects inflated major versions ($\ge 5.0$, $\ge 10.0$, $\ge 50.0$) on recently registered packages while safely recognizing legitimate CalVer (`YYYY.M.D`) and Date-stamp (`YYYYMM`/`YYYYMMDD`) versioning schemes.
   - Emits `SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION` (+15 to +40 pts) and exposes `ui_facets` with database covering indexes for fast UI filtering.
8. **Taxonomy Gap Intelligence & Reprocessing Pipeline**:
   - Analyzes registered ecosystem package catalogs to surface frequent naming tokens absent from current brand taxonomies (`sentinel taxonomy-gap-report`).
   - Background Job Queue (`sentinel.scheduler.jobs`) supporting targeted re-scoring, keyword filters, and cache invalidation workflows.
9. **Multi-Ecosystem Lockfile Linter (`sentinel check`)**:
   - Audits `requirements.txt`, `Pipfile`, `package.json`, and lockfiles for hallucinated or unverified dependencies.
10. **Local Disk Cache Manager**:
    - Caches registry snapshots, metadata JSON, and immutable release tarballs on disk to reduce network bandwidth by up to 99%.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
* Python 3.10 or higher
* SQLite 3.35+ (built into Python)

### 2. Setup Virtual Environment
```bash
git clone https://github.com/royans/sentinel.git
cd sentinel

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 3. Verify Test Suite
```bash
pytest -v tests/
```

---

## 💻 CLI Commands

### 1. Sync Upstream Registry Catalog
Download and index registered package catalogs into local SQLite:
```bash
# Sync PyPI (870k+ packages)
sentinel sync-index --ecosystem pypi

# Sync npm
sentinel sync-index --ecosystem npm
```

### 2. Generate Long-Tail Watchlist Matrix
Compute un-registered candidate permutations across enterprise taxonomies:
```bash
sentinel generate-matrix --ecosystem pypi --limit 50000
```

### 3. Triage & Rank Suspicious Packages
Run the progressive 4-tier evaluator to rank packages by threat score:
```bash
sentinel triage --ecosystem pypi --limit 25
```

### 4. Real-Time Inbound Feed Tripwire
Poll upstream release feeds to detect newly squatted packages against the watchlist in $< 1\text{ ms}$:
```bash
sentinel poll --ecosystem pypi --limit 50
sentinel poll --ecosystem npm --limit 50
```

### 5. Prioritized Crawl & Freshness Re-Audit Cycle
Run a prioritized batch inspection over inbound releases, high-risk brand targets, due freshness re-checks, and historical backfills:
```bash
sentinel crawl-cycle --limit 50 --brands "google,azure,aws,okta,discord,clerk,stripe,supabase"
```

### 6. Retroactive Catalog Audit
Scan registered package catalogs against combinatorial candidate grammars:
```bash
sentinel audit-catalog --ecosystem pypi --limit 50000
```

### 7. Audit Lockfiles & Project Dependencies
Scan project configuration for hallucinated or unverified dependencies:
```bash
sentinel check requirements.txt
sentinel check package.json
```

### 8. Inspect Upstream Package Tarball
Perform deep static AST inspection on any package:
```bash
sentinel inspect requests --ecosystem pypi
sentinel inspect express --ecosystem npm
```

### 9. Preemptive Brand Claim Advisory
Generate prioritized registration checklists for your brand:
```bash
sentinel advisory --brand "Okta"
sentinel advisory --brand "Stripe"
```

### 10. Export Static Dossiers & Search Index
Generate Markdown dossiers with YAML frontmatter, rolling JSON feeds, and search indexes for FlagThis.com:
```bash
sentinel export-flagthis --output-dir reports/flagthis_export
```

### 11. Local Cache Statistics
Inspect local disk cache usage and network bandwidth savings:
```bash
sentinel cache-stats
```

### 12. View Threat Detections Report
Display recent threat detections directly in terminal tables:
```bash
sentinel report --limit 25
```

### 13. Mark Grammar Matching Packages
Populate candidate grammar match flags across the catalog to constrain backfill crawling:
```bash
sentinel mark-grammar-matches --ecosystem pypi
sentinel mark-grammar-matches --ecosystem npm
```

### 14. Taxonomy Gap Intelligence Report
Analyze registered package naming tokens against current taxonomies to find high-frequency unmapped brands:
```bash
sentinel taxonomy-gap-report --ecosystem pypi --top 50
```

### 15. Backfill Code Execution Flags
Recompute `has_install_hook` and `has_network_socket` boolean fields across existing detections from stored AST signals:
```bash
sentinel backfill-install-hooks
```

### 16. Audit Daily Compliance
Verify that no package exceeded the 1-review-per-day rule across crawl workers:
```bash
sentinel audit-compliance --date 2026-08-29
```

### 17. Batch Reprocessing & Recalculation Queue
Manage asynchronous queue recalculations and flag packages for re-evaluation:
```bash
sentinel flag-reprocess --all-suspicious
sentinel run-reprocess --limit 100
sentinel queue-status
```

### 18. Run Automated Cron Cycle
Execute a complete automated cycle (stream check $\rightarrow$ AST evaluation $\rightarrow$ static export):
```bash
sentinel run-cycle --timeout 300
```

---

## ⏰ Automated Cron Setup

Run Sentinel periodically (e.g. every 20 minutes) to continuously monitor streams, reprocess queues, and evaluate candidate packages:

```bash
crontab -e
```

Add the following line:
```cron
*/20 * * * * cd /path/to/sentinel && ./scripts/cron_sentinel.sh >> logs/sentinel_cron.log 2>&1
```

---

## 📊 Architecture

```
[ PyPI RSS / npm CouchDB Feed ]
               │
               ▼
┌────────────────────────────────────────┐
│ In-Memory Watchlist Hash Match (O(1))  │  < 1 ms / event
└──────────────────┬─────────────────────┘
                   │ (Candidate Triggered)
                   ▼
┌────────────────────────────────────────┐
│ Multi-Tier Priority Crawler & Worker   │
│ Tier 1: Inbound New Releases (1000+)   │
│ Tier 2: Brand Watchlist (Google/Azure) │
│ Tier 3: Due Exponential Freshness      │
│ Tier 4: Grammar-Scoped Backfill        │
│ Gate: Daily Review Log (1 audit/day)   │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ Progressive Multi-Tier Assessor        │
│ 1. Official Vendor Domain Proof        │
│ 2. Metadata & Package Effort Signals   │
│ 3. Deep Static AST & YARA Threat Engine│
│    - PyPI: setup.py + build-backend    │
│    - npm:  package.json + tarball .js  │
│    - YARA: 70 rules across 9 suites    │
│ 4. Composite Risk Scorer (0-1000)      │
│    - Deploy-time execution indexing    │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ SQLite WAL Database & FlagThis Exporter│
│ - Dossiers & Inverted Search Index     │
│ - DB Sync (flagthis.com/sentinel)      │
└────────────────────────────────────────┘
```

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
