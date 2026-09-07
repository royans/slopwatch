# ⚙️ SlopWatch Configuration Guide: Whitelisting & Alert Policies

SlopWatch is designed to be **zero-config by default**—it works out-of-the-box on any project without requiring configuration files or API keys.

However, real-world development workflows often require **whitelisting private internal packages** (e.g. proprietary company libraries not published to public PyPI/npm) or **tuning alert severity levels** for CI/CD pipelines.

This guide details how to configure SlopWatch via `.slopwatch.yaml` or `pyproject.toml`.

---

## 🚀 1-Second Setup: `slopwatch init`

The fastest way to generate a baseline configuration is running `slopwatch init` in your project root:

```bash
slopwatch init
```

This command automatically:
1. Inspects your workspace and identifies dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`, etc.).
2. Generates a fully annotated `.slopwatch.yaml` configuration file.
3. Installs a native Git pre-commit hook (`.git/hooks/pre-commit`).
4. Generates a GitHub Actions workflow (`.github/workflows/slopwatch.yml`).
5. Writes an `AGENTS.md` rule telling autonomous coding agents to run `slopwatch check` before adding a dependency (appended if the file already exists).
6. Runs an initial baseline audit across all discovered manifests.

---

## 📁 Configuration File Locations

SlopWatch automatically discovers configuration in the project root or any parent directory up to your git root. It checks the following locations in order:

1. `.slopwatch.yaml` / `.slopwatch.yml` (Recommended)
2. `pyproject.toml` (under the `[tool.slopwatch]` table)

---

## 📝 Configuration File Reference

### Example: `.slopwatch.yaml`

```yaml
# SlopWatch Project Configuration (.slopwatch.yaml)
version: 1

# 1. Package Allowlist (Whitelisting)
# Packages listed here will NEVER be flagged for hallucination or typosquatting.
# Useful for internal private packages, company SDKs, or approved direct VCS forks.
# An entry may be a bare name, or a mapping carrying a justification that is
# echoed in the suppression ledger and in --json output.
allowlist:
  - "my-internal-company-sdk"
  - "@company/private-client-v2"
  - "git+https://github.com/my-org/custom-fork.git"
  - name: "company-auth-token-helper"
    reason: "internal package on Artifactory; approved 2026-09 (SEC-412)"

# 1b. Ignore specific finding codes (see docs/FINDINGS.md).
# Demotes a finding from build-breaking to advisory. Suppressed findings are
# NOT hidden — they appear in the run output under the suppression ledger and
# in --json under "suppressions".
ignore:
  - "SLOP-0004"   # accept direct VCS / raw-URL dependencies in this repo

# 2. Alert & Failure Policy (Exit Code Trigger)
# Determines the minimum severity that causes `slopwatch check` or `audit` to fail CI (exit code 1).
# Options:
#   - "CRITICAL": Fail CI only on confirmed active malware / weaponized hooks (score >= 80)
#   - "HIGH":     Fail CI on typosquats, direct unpinned URLs, or confirmed malware (score >= 50) [DEFAULT]
#   - "MEDIUM":   Fail CI on unlisted 404 dependencies, high-risk obfuscation, or higher (score >= 35)
#   - "ANY":      Fail CI on any warning or advisory
fail_on: "HIGH"

# 3. Numeric Score Threshold (0-100)
# Optional override for the numeric threat score that triggers a build failure.
# Default aligns with fail_on: CRITICAL=80, HIGH=50, MEDIUM=35, ANY=1
min_threat_score: 50

# 4. Offline Mode
# Set to true to disable live HTTP registry queries (runs offline heuristics & local signatures only).
# Default: false
offline: false

# 5. Path Ignore Patterns
# Glob patterns to skip during directory-wide scans (`slopwatch audit .`)
ignore_paths:
  - "tests/**"
  - "fixtures/**"
  - "examples/**"
  - "node_modules/**"
```

---

### Example: `pyproject.toml`

For Python projects that prefer keeping all tool configurations in `pyproject.toml`:

```toml
[tool.slopwatch]
allowlist = [
    "my-internal-company-sdk",
    "company-auth-token-helper",
    "git+https://github.com/my-org/custom-fork.git",
]
ignore = ["SLOP-0004"]
fail_on = "HIGH"
min_threat_score = 50
offline = false
ignore_paths = [
    "tests/**",
    "fixtures/**",
]
```

---

## 🛡️ Whitelisting Internal & Private Packages (`allowlist`)

### Why Whitelisting is Needed
By default, `slopwatch check` queries the public PyPI or npm registry to confirm that declared dependencies actually exist:
* If an AI assistant (Cursor, Copilot, ChatGPT) invents a fake package name (e.g. `fastapi-azure-auth-toolkit`), the registry returns **404 Not Found**, and SlopWatch flags it as `UNREGISTERED_OR_HALLUCINATED_PACKAGE`.
* However, if your team maintains a **private internal package** on a private index (Artifactory, AWS CodeArtifact, Nexus) that is not published to public PyPI/npm, public registry queries will also return 404.

### How Whitelisting Works
When a package name is listed in `allowlist`:
1. SlopWatch **skips** public registry lookup for that package.
2. SlopWatch **suppresses** brand typosquatting heuristics for that package.
3. Direct VCS URLs matching the allowlist are permitted.

### Name Normalization in the Allowlist
SlopWatch normalizes package names automatically:
* In Python, `My_Internal.SDK` matches `my-internal-sdk` (per PEP 503).
* In npm, scoped packages like `@myorg/auth` are preserved and matched accurately.

---

## 🚨 Alert Levels & Default Rubric

SlopWatch classifies security findings into four distinct severity tiers:

| Severity | Default Score Range | Findings Included | Default CI Action (`fail_on: HIGH`) |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | **80 – 100** | Confirmed install-time weaponization, reverse shells, raw socket calls, `setup.py` cmdclass execution, malicious `.pth` startup files, Discord webhook credential stealers, npm `preinstall` stealer scripts. | **FAILS CI (Exit Code 1)** |
| **`HIGH`** | **50 – 79** | Typosquats of high-value brands (Stripe, Okta, Supabase, Google, AWS), unpinned direct VCS dependencies (`git+https://...`), dense hex-string obfuscation. | **FAILS CI (Exit Code 1)** |
| **`MEDIUM`** | **35 – 49** | Unregistered / 404 packages on public registry (AI hallucination risk), suspicious dynamic loaders without verified network sinks, unexpected compiled native binaries. | **Advisory Warning (Exit 0)** |
| **`LOW` / `INFO`** | **0 – 34** | Standard environment variable access (`os.environ`), benign community telemetry, empty documentation stubs. | **Passed (Exit 0)** |

### A note on `UNVERIFIED_HIGH_SIGNAL`

SlopWatch's verdict layer includes a sixth verdict, `UNVERIFIED_HIGH_SIGNAL`:
the total score crossed a threat threshold, but no individual signal behind
it was, on its own, strong enough to confidently assert malice (see the
"Honest about uncertainty" point in the main README). Today, this table's
`fail_on` policy is driven purely by **score**, not by verdict — so a package
that lands on `UNVERIFIED_HIGH_SIGNAL` still fails CI at exactly the same
score threshold a confirmed `MALICIOUS`/`SUSPICIOUS` result would. Whether
that's the right default (vs. treating it as an advisory-only tier
regardless of score) is an open question, not yet decided — if you want a
softer default for now, add packages you've manually reviewed to
`allowlist`, or suppress the specific finding code with `--ignore SLOP-0001`
(or an `ignore:` list in `.slopwatch.yaml`). See
[FINDINGS.md](FINDINGS.md) for the finding-code catalog.

### Choosing Your `fail_on` Policy

* **`fail_on: "CRITICAL"` (Permissive)**:
  * Recommended during initial onboarding or legacy migrations.
  * Only breaks builds on confirmed malware or weaponized install hooks. Unlisted dependencies emit an advisory warning but do not block CI.
* **`fail_on: "HIGH"` (Default & Recommended)**:
  * Recommended for all modern software projects.
  * Blocks active malware, brand typosquats, and unvetted direct URL dependencies.
* **`fail_on: "MEDIUM"` (Strict Zero-Trust)**:
  * Recommended for high-security environments, financial services, or autonomous AI coding agent workflows.
  * Blocks any unlisted 404 package, ensuring every single dependency is verified on the public registry or explicitly declared in `allowlist`.

---

## ⚡ CLI Flag Overrides

CLI flags always take precedence over configuration file settings:

| CLI Option | Description |
| :--- | :--- |
| `--offline` | Disables live HTTP registry validation; runs offline heuristics only. |
| `--ignore CODE` | (`check`) Demotes a finding code (e.g. `SLOP-0003`) from build-breaking to advisory. Repeatable. Accepts a code or a full reason string. |
| `--stats` | (`check`) Prints run statistics: manifests audited, dependencies scanned, live registry calls, and wall time. |
| `--strict` | Enforces strict zero-warning mode on directory audits. |
| `--force` | Overwrites existing configuration and hooks in `slopwatch init`. |

### Suppression ledger

Whenever a finding is suppressed — by `allowlist` or by `ignore` / `--ignore` —
SlopWatch still reports it, listed separately from the flagged findings and
never counted against the `fail_on` policy:

```
                Suppressions (not counted against policy)
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package           ┃ Via                ┃ Why                          ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ company-auth-...  │ allowlist          │ approved 2026-09 (SEC-412)    │
│ reqeusts          │ ignore (SLOP-0003) │ finding code in ignore list   │
└───────────────────┴────────────────────┴──────────────────────────────┘
```

In `--json` output the same information is under `suppressions`, and every
flagged finding carries its stable `code`.

---

## 📋 Defaults Summary

If no configuration file is present, SlopWatch applies these defaults:

* **`allowlist`**: Empty (`[]`)
* **`ignore`**: Empty (`[]`) — no finding codes suppressed
* **`fail_on`**: `"HIGH"` (fails on score $\ge 50$ or severity `HIGH`/`CRITICAL`)
* **`min_threat_score`**: `50`
* **`offline`**: `false` (validates upstream registries live)
* **`timeout`**: `5.0s` per upstream registry query
