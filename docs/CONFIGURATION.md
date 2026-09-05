# ⚙️ SlopGuard Configuration Guide: Whitelisting & Alert Policies

SlopGuard is designed to be **zero-config by default**—it works out-of-the-box on any project without requiring configuration files or API keys.

However, real-world development workflows often require **whitelisting private internal packages** (e.g. proprietary company libraries not published to public PyPI/npm) or **tuning alert severity levels** for CI/CD pipelines.

This guide details how to configure SlopGuard via `.slopguard.yaml` or `pyproject.toml`.

---

## 🚀 1-Second Setup: `slopguard init`

The fastest way to generate a baseline configuration is running `slopguard init` in your project root:

```bash
slopguard init
```

This command automatically:
1. Inspects your workspace and identifies dependency manifests (`requirements.txt`, `pyproject.toml`, `package.json`, etc.).
2. Generates a fully annotated `.slopguard.yaml` configuration file.
3. Installs a native Git pre-commit hook (`.git/hooks/pre-commit`).
4. Generates a GitHub Actions workflow (`.github/workflows/slopguard.yml`).
5. Runs an initial baseline audit across all discovered manifests.

---

## 📁 Configuration File Locations

SlopGuard automatically discovers configuration in the project root or any parent directory up to your git root. It checks the following locations in order:

1. `.slopguard.yaml` / `.slopguard.yml` (Recommended)
2. `pyproject.toml` (under the `[tool.slopguard]` table)

---

## 📝 Configuration File Reference

### Example: `.slopguard.yaml`

```yaml
# SlopGuard Project Configuration (.slopguard.yaml)
version: 1

# 1. Package Allowlist (Whitelisting)
# Packages listed here will NEVER be flagged for hallucination or typosquatting.
# Useful for internal private packages, company SDKs, or approved direct VCS forks.
allowlist:
  - "my-internal-company-sdk"
  - "company-auth-token-helper"
  - "@company/private-client-v2"
  - "git+https://github.com/my-org/custom-fork.git"

# 2. Alert & Failure Policy (Exit Code Trigger)
# Determines the minimum severity that causes `slopguard check` or `audit` to fail CI (exit code 1).
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
# Glob patterns to skip during directory-wide scans (`slopguard audit .`)
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
[tool.slopguard]
allowlist = [
    "my-internal-company-sdk",
    "company-auth-token-helper",
    "git+https://github.com/my-org/custom-fork.git",
]
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
By default, `slopguard check` queries the public PyPI or npm registry to confirm that declared dependencies actually exist:
* If an AI assistant (Cursor, Copilot, ChatGPT) invents a fake package name (e.g. `fastapi-azure-auth-toolkit`), the registry returns **404 Not Found**, and SlopGuard flags it as `UNREGISTERED_OR_HALLUCINATED_PACKAGE`.
* However, if your team maintains a **private internal package** on a private index (Artifactory, AWS CodeArtifact, Nexus) that is not published to public PyPI/npm, public registry queries will also return 404.

### How Whitelisting Works
When a package name is listed in `allowlist`:
1. SlopGuard **skips** public registry lookup for that package.
2. SlopGuard **suppresses** brand typosquatting heuristics for that package.
3. Direct VCS URLs matching the allowlist are permitted.

### Name Normalization in the Allowlist
SlopGuard normalizes package names automatically:
* In Python, `My_Internal.SDK` matches `my-internal-sdk` (per PEP 503).
* In npm, scoped packages like `@myorg/auth` are preserved and matched accurately.

---

## 🚨 Alert Levels & Default Rubric

SlopGuard classifies security findings into four distinct severity tiers:

| Severity | Default Score Range | Findings Included | Default CI Action (`fail_on: HIGH`) |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | **80 – 100** | Confirmed install-time weaponization, reverse shells, raw socket calls, `setup.py` cmdclass execution, malicious `.pth` startup files, Discord webhook credential stealers, npm `preinstall` stealer scripts. | **FAILS CI (Exit Code 1)** |
| **`HIGH`** | **50 – 79** | Typosquats of high-value brands (Stripe, Okta, Supabase, Google, AWS), unpinned direct VCS dependencies (`git+https://...`), dense hex-string obfuscation. | **FAILS CI (Exit Code 1)** |
| **`MEDIUM`** | **35 – 49** | Unregistered / 404 packages on public registry (AI hallucination risk), suspicious dynamic loaders without verified network sinks, unexpected compiled native binaries. | **Advisory Warning (Exit 0)** |
| **`LOW` / `INFO`** | **0 – 34** | Standard environment variable access (`os.environ`), benign community telemetry, empty documentation stubs. | **Passed (Exit 0)** |

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
| `--strict` | Enforces strict zero-warning mode on directory audits. |
| `--force` | Overwrites existing configuration and hooks in `slopguard init`. |

---

## 📋 Defaults Summary

If no configuration file is present, SlopGuard applies these defaults:

* **`allowlist`**: Empty (`[]`)
* **`fail_on`**: `"HIGH"` (fails on score $\ge 50$ or severity `HIGH`/`CRITICAL`)
* **`min_threat_score`**: `50`
* **`offline`**: `false` (validates upstream registries live)
* **`timeout`**: `5.0s` per upstream registry query
