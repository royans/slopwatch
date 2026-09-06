"""
Sentinel npm Tarball Source Code Inspector.

Downloads and pattern-scans the actual JS/TS source inside an npm tarball for
dangerous runtime behavior, closing the gap where package.json only declares
lifecycle scripts but the real payload executes at require()-time or is merely
referenced from an innocuous-looking install hook (e.g. "postinstall": "node
setup.js", where setup.js itself was never otherwise inspected).

Deliberately regex/heuristic-based rather than a full JS/TS parser, to avoid
adding a heavy new dependency — consistent with the project's zero-LLM,
low-resource design. Mirrors slopwatch.assessor.python_ast's philosophy of
separating "this pattern exists somewhere" (informational) from "this specific
dangerous combination was observed" (confirmed-dangerous), applied to JS.
"""

import io
import ipaddress
import re
import tarfile
from typing import Dict, List, Tuple

from slopwatch.core.dto import ASTSecurityReport, ThreatVerdict
from slopwatch.assessor.yara_engine import get_yara_scanner

SOURCE_FILE_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts")
SKIP_PATH_SUBSTRINGS = (
    "node_modules/", "/test/", "/tests/", "/__tests__/", "/.git/", "/coverage/",
    "/fixtures/", "/fixture/", "/__fixtures__/", "/__mocks__/", "/mocks/", "/mock/",
    "/testutils/", "/test-utils/", "/e2e/", "/spec/", "/specs/",
    "/samples/", "/examples/", "/docs/", "/documentation/", "/.github/",
    "/vendor/", "/vendored/", "/third_party/", "/third-party/",
    "/_vendor/", "/extern/", "/external/", "/deps/", "/templates/", "/template/",
)

TEST_FILE_SUFFIXES = (
    ".test.js", ".test.ts", ".test.jsx", ".test.tsx", ".test.cjs", ".test.mjs",
    ".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx", ".spec.cjs", ".spec.mjs",
    ".mock.js", ".mock.ts", ".mock.cjs", ".mock.mjs",
)


def _is_test_or_fixture_path(path: str) -> bool:
    """True if path is within a test/fixture/sample directory or is a test/spec file."""
    normalized = ("/" + path.replace("\\", "/").strip("/")).lower()
    if any(sub in normalized for sub in SKIP_PATH_SUBSTRINGS):
        return True
    filename = normalized.split("/")[-1]
    if any(filename.endswith(sfx) for sfx in TEST_FILE_SUFFIXES):
        return True
    if filename.startswith("test.") or filename.startswith("spec.") or filename.startswith("mock."):
        return True
    return False


# Resource bounds — keep this bounded even against a package with thousands of
# files or a multi-hundred-MB tarball (npm packages can legitimately be huge).
MAX_FILES_SCANNED = 500
MAX_BYTES_PER_FILE = 2 * 1024 * 1024        # skip individual files larger than this
MAX_TOTAL_BYTES_SCANNED = 20 * 1024 * 1024  # stop actively scanning content past this cumulative size

EXEC_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\beval\s*\("), "eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()"),
    (re.compile(r"require\s*\(\s*['\"`]child_process['\"`]\s*\)"), "require('child_process')"),
    (re.compile(r"require\s*\(\s*`[^`]*child_process[^`]*`\s*\)"), "require(`child_process`)"),
    (re.compile(r"\b(?:globalThis|window|global)\s*\[\s*['\"`]eval['\"`]\s*\]"), "globalThis['eval']"),
    (re.compile(r"\bprocess\s*\.\s*(?:binding|mainModule)\b"), "process.binding/mainModule"),
    (re.compile(r"\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFileSync\s*\("), "execSync/spawnSync"),
]
DANGEROUS_EVAL_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\beval\s*\("), "eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()"),
    (re.compile(r"\bvm\s*\.\s*(?:runInContext|runInNewContext|runInThisContext)\s*\("), "vm.runInContext"),
]
DECODE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"Buffer\.from\([^)]{0,120},\s*['\"]base64['\"]\s*\)"), "Buffer.from(..., 'base64')"),
    (re.compile(r"\batob\s*\("), "atob()"),
]
NETWORK_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"require\s*\(\s*['\"]https?['\"]\s*\)"), "require('http(s)')"),
    (re.compile(r"\bfetch\s*\(|\baxios\.[a-z]+\s*\(|\bXMLHttpRequest\b"), "fetch/axios/XMLHttpRequest"),
]
ENV_VARS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bprocess\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])"), "process.env"),
]
SENSITIVE_ENV_VARS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"process\.env\.(?:AWS_[A-Z_]*KEY|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|SLACK_[A-Z_]*TOKEN|DISCORD_[A-Z_]*TOKEN|PRIVATE_KEY|SECRET_KEY|API_KEY|ACCESS_TOKEN)\b", re.IGNORECASE), "Sensitive Token Harvesting"),
    (re.compile(r"(?:JSON\.stringify|Object\.(?:keys|values|entries))\s*\(\s*process\.env\s*\)", re.IGNORECASE), "Bulk Environment Harvesting"),
]

EXFILTRATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", re.IGNORECASE), "Discord Webhook"),
    (re.compile(r"https?://api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+", re.IGNORECASE), "Telegram Bot API"),
    (re.compile(r"https?://[a-zA-Z0-9_-]+\.(?:webhook\.site|pipedream\.net|interact\.sh|oastify\.com|burpcollaborator\.net|requestcatcher\.com|beeceptor\.com)", re.IGNORECASE), "OAST / Callback Service"),
    (re.compile(r"https?://[a-zA-Z0-9_-]+\.(?:ngrok-free\.app|ngrok\.io|localtunnel\.me|serveo\.net)", re.IGNORECASE), "Tunneling Service"),
    (re.compile(r"https?://api\.github\.com/gists\b", re.IGNORECASE), "GitHub Gists API Exfiltration (Dead Drop)"),
    (re.compile(r"https?://gitlab\.com/api/v4/snippets\b", re.IGNORECASE), "GitLab Snippets API Exfiltration"),
    (re.compile(r"https?://(?:pastebin\.com/api|hastebin\.com/documents|ghostbin\.com/paste)", re.IGNORECASE), "Pastebin API Exfiltration"),
    (re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"), "Hardcoded GitHub Personal Access Token"),
    (re.compile(r"ssl\._create_unverified_context|check_hostname\s*=\s*False|verify_mode\s*=\s*(?:ssl\.)?CERT_NONE|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\x27\x220]", re.IGNORECASE), "TLS / SSL Verification Bypass (Defense Evasion)"),
]

_RAW_IP_URL_RE = re.compile(
    r"https?://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?::[0-9]{2,5})?",
    re.IGNORECASE,
)


def _is_public_exfil_ip(ip_str: str) -> bool:
    """Return True only if IP is a routable public IP (not local, private, test, link-local, or documentation)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
        octets = ip_str.split(".")
        if len(octets) == 4:
            first = int(octets[0])
            second = int(octets[1])
            third = int(octets[2])
            if first == 198 and second == 51 and third == 100:  # TEST-NET-2 (RFC 5737)
                return False
            if first == 192 and second == 0 and third == 2:     # TEST-NET-1 (RFC 5737)
                return False
            if first == 203 and second == 0 and third == 113:   # TEST-NET-3 (RFC 5737)
                return False
            if first == 100 and (64 <= second <= 127):          # CGNAT (RFC 6598)
                return False
        return True
    except ValueError:
        return False


CREDENTIAL_PATH_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.aws/credentials|\.aws/config)", re.IGNORECASE), "AWS Credentials (~/.aws/credentials)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/id_ecdsa|\.ssh/authorized_keys)", re.IGNORECASE), "SSH Private Keys (~/.ssh)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/\.ssh(?:\b|/|\b)", re.IGNORECASE), "SSH Directory / Private Keys (~/.ssh)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.yarnrc|\.gitconfig)", re.IGNORECASE), "Registry / Git Configuration (~/.yarnrc, ~/.gitconfig)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.config/gcloud/(?:application_default_credentials\.json|properties)|\.azure/(?:azureProfile|accessTokens)\.json|\.config/doctl/config\.yaml)", re.IGNORECASE), "Cloud Provider Credentials (GCP, Azure, DigitalOcean)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.terraform\.d/credentials\.tfrc\.json|\.vault-token|\.pgpass|\.netrc)", re.IGNORECASE), "Infrastructure & DB Credentials (~/.terraform.d, ~/.vault-token, ~/.pgpass, ~/.netrc)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/\.(?:bash|zsh|python|sh)_history\b", re.IGNORECASE), "Shell Command History (~/.bash_history, ~/.zsh_history)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.npmrc|\.pypirc|\.git-credentials)", re.IGNORECASE), "Registry / Git Credentials (~/.npmrc, ~/.pypirc)"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|[A-Za-z]:\\Users\\[^\\]+)/(?:\.kube/config|\.docker/config\.json)", re.IGNORECASE), "Kube / Docker Credentials"),
    (re.compile(r"(?:Google/Chrome|BraveSoftware/Brave-Browser|Microsoft/Edge)/User Data/Default/(?:Login Data|Local State|Cookies)", re.IGNORECASE), "Browser Credentials / Cookies"),
    (re.compile(r"\b(?:nkbihfbeogaeaoehlefnkodbefgpgknn|ibnejdfjmmkpcnlpebklmnkoeoihofec|bfnaelmomeimhlpmgjnjophhpkkoljpa)\b", re.IGNORECASE), "Crypto Wallet Extension Storage"),
    (re.compile(r"/etc/(?:shadow|passwd)\b"), "System Credentials (/etc/shadow, /etc/passwd)"),
    (re.compile(r"(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal/computeMetadata/v1|metadata/identity/oauth2/token|latest/api/token\b)", re.IGNORECASE), "Cloud Instance Metadata (AWS/GCP/Azure IMDS)"),
    (re.compile(r"/var/run/secrets/kubernetes\.io/serviceaccount(?:/token)?", re.IGNORECASE), "Kubernetes Service Account Token"),
    (re.compile(r"\bVAULT_TOKEN\b|127\.0\.0\.1:8200", re.IGNORECASE), "HashiCorp Vault Credentials / Endpoint"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|%APPDATA%|Library/Application Support)/[^\s\x22\x27\)]*(?:\.(?:vscode|claude|gemini|cursor)|Claude|Cursor)/(?:settings|tasks|rules|mcp|claude_desktop_config|\.cursorrules)|(?:\b|^|/)(\.cursorrules|claude_desktop_config\.json|mcp\.json|setup-chrome-mcp|chrome-mcp)(?:\b|$)", re.IGNORECASE), "IDE / AI Agent Configuration Hijacking"),
]

CROSS_ECOSYSTEM_WORM_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"upload\.pypi\.org/legacy/", re.IGNORECASE), "PyPI Registry Upload Endpoint (Worm Replication)"),
    (re.compile(r"\bhandlePypiTokens\b|\bhandleNpmTokens\b|\bhandleRubygemsTokens\b"), "Cross-Ecosystem Token Validator (Shai-Hulud Worm)"),
    (re.compile(r"pypi-[A-Za-z0-9_-]{30,}"), "PyPI Token Harvesting / Probing"),
    (re.compile(r"github\.com/(?:oven-sh/bun|denoland/deno|indygreg/python-build-standalone)/releases/download/", re.IGNORECASE), "Automated Secondary Runtime Dropper (Bun/Deno/Python)"),
    (re.compile(r"nodejs\.org/dist/v[0-9.]+/node-v[0-9.]+", re.IGNORECASE), "Automated Portable Node.js Dropper"),
    (re.compile(r"\bdetectHardenRunner\b|\bRunner\.Worker\b|\bdumpMemory\b"), "CI Runner Memory Dump / Evasion"),
]

GYP_WEAPONIZED_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"__subclasses__", re.IGNORECASE), "Python __subclasses__ Sandbox Escape"),
    (re.compile(r"catch_warnings", re.IGNORECASE), "catch_warnings builtins traversal"),
    (re.compile(r"__import__\s*\(\s*['\"]os['\"]\s*\)\.system", re.IGNORECASE), "os.system execution"),
    (re.compile(r"node\s+[\w.-]+\.js", re.IGNORECASE), "Loose Node script execution from gyp"),
]

NATIVE_BINARY_EXTENSIONS = (".so", ".dll", ".dylib", ".exe", ".elf")

# How close (in characters) an execution primitive and a decode/network call must
# appear to count as plausibly the same statement/chain — e.g. `fetch(x).then(r =>
# eval(r))` or `eval(atob(x))`. A bare "both patterns exist somewhere in this file"
# is far too loose: large bundled third-party libraries (jQuery, Angular, D3,
# web3.js) routinely contain eval()/new Function() AND fetch()/XHR somewhere across
# thousands of lines with zero relationship between them. Confirmed in production:
# the file-level version of this check false-triggered MALICIOUS on 10 legitimate
# npm packages (vendored jQuery/Angular/D3/web3 bundles) before this fix.
PROXIMITY_WINDOW_CHARS = 400


def _scan_file_content(content: str, filename: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Scan one file's text for dangerous JS runtime patterns.
    Uses high-performance compiled YARA rules with regex heuristic fallback.
    Returns (flags, line_details) as lists of (dedup_key, rendered_text) pairs —
    dedup_key lets the caller collapse repeats of the same pattern across many
    files (e.g. several vendored copies of the same bundled library) without
    losing where it was first observed.
    """
    yara_scanner = get_yara_scanner()
    if yara_scanner.is_available:
        return yara_scanner.scan_file_content(content, filename)

    flags: List[Tuple[str, str]] = []
    line_details: List[Tuple[str, str]] = []
    exec_positions: List[int] = []
    eval_positions: List[int] = []
    decode_or_network_positions: List[int] = []
    env_positions: List[int] = []
    sensitive_env_positions: List[int] = []
    exfil_positions: List[int] = []
    cred_positions: List[int] = []

    def _scan_group(patterns, prefix, position_list):
        for pattern, label in patterns:
            m = pattern.search(content)
            if m:
                position_list.append(m.start())
                lineno = content.count("\n", 0, m.start()) + 1
                flags.append((f"{prefix}:{label}", f"{prefix}: '{label}' found in {filename}:{lineno}"))
                line_details.append((f"{prefix}:{label}", f"{filename}:{lineno} -> {label}"))

    _scan_group(EXEC_PATTERNS, "SOURCE_CODE_DYNAMIC_EXECUTION", exec_positions)
    _scan_group(DANGEROUS_EVAL_PATTERNS, "SOURCE_CODE_DYNAMIC_EXECUTION", eval_positions)
    _scan_group(DECODE_PATTERNS, "SOURCE_CODE_ENCODED_PAYLOAD", decode_or_network_positions)
    _scan_group(NETWORK_PATTERNS, "SOURCE_CODE_NETWORK_CALL", decode_or_network_positions)
    _scan_group(ENV_VARS_PATTERNS, "SOURCE_CODE_ENV_VARS_ACCESS", env_positions)
    _scan_group(SENSITIVE_ENV_VARS_PATTERNS, "SOURCE_CODE_ENV_VARS_ACCESS", sensitive_env_positions)
    _scan_group(EXFILTRATION_PATTERNS, "EXFILTRATION_DESTINATION_DETECTED", exfil_positions)

    # Check raw public IPs with rigorous routability validation
    for m in _RAW_IP_URL_RE.finditer(content):
        ip_str = m.group(1)
        if _is_public_exfil_ip(ip_str):
            exfil_positions.append(m.start())
            lineno = content.count("\n", 0, m.start()) + 1
            label = "Raw Public IP Endpoint"
            flags.append((f"EXFILTRATION_DESTINATION_DETECTED:{label}", f"EXFILTRATION_DESTINATION_DETECTED: '{label}' found in {filename}:{lineno}"))
            line_details.append((f"EXFILTRATION_DESTINATION_DETECTED:{label}", f"{filename}:{lineno} -> {label} ({ip_str})"))

    _scan_group(CREDENTIAL_PATH_HARVESTING := CREDENTIAL_PATH_PATTERNS, "CREDENTIAL_PATH_HARVESTING", cred_positions)
    worm_positions: List[int] = []
    _scan_group(CROSS_ECOSYSTEM_WORM_PATTERNS, "CROSS_ECOSYSTEM_WORM_PROPAGATION", worm_positions)

    # Dynamic code loader: triggers only when an actual eval/execution primitive is near decode/network
    is_loader = any(
        abs(e - d) <= PROXIMITY_WINDOW_CHARS
        for e in eval_positions
        for d in decode_or_network_positions
    )
    if is_loader:
        key = "SOURCE_CODE_DYNAMIC_CODE_LOADER"
        flags.append((key, f"{key}: execution primitive combined with decode/network call in {filename}"))
        line_details.append((key, f"{filename} -> dynamic code loader (eval/exec + decode/network within {PROXIMITY_WINDOW_CHARS} chars)"))

    # Detect suspected stealer signature: exfiltration endpoint combined with secret/sensitive token harvesting
    is_stealer = any(
        abs(e - c) <= PROXIMITY_WINDOW_CHARS
        for e in exfil_positions
        for c in (cred_positions + sensitive_env_positions)
    )
    if is_stealer:
        key = "SOURCE_CODE_CONFIRMED_STEALER"
        flags.append((key, f"{key}: potential exfiltration endpoint combined with credential/environment harvesting in {filename}"))
        line_details.append((key, f"{filename} -> suspected information stealer (exfiltration endpoint + secret access within {PROXIMITY_WINDOW_CHARS} chars)"))

    return flags, line_details


def analyze_npm_package_tarball(tarball_bytes: bytes, package_name: str) -> ASTSecurityReport:
    """Extract and pattern-scan the real JS/TS source inside an npm tarball."""
    # Keyed by dedup_key -> rendered text, so the same pattern found across many
    # near-duplicate files (e.g. a bundle vendored under both dist/ and src/, or
    # minified + unminified copies) is reported once, not once per file. Without
    # this, a package vendoring 5 copies of the same library scored 5x higher than
    # one vendoring a single copy, purely from restating the same evidence.
    flag_by_key: Dict[str, str] = {}
    line_by_key: Dict[str, str] = {}
    occurrence_counts: Dict[str, int] = {}
    total_source_files = 0
    total_loc = 0
    total_bytes = 0
    files_scanned = 0
    bytes_scanned = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:*") as tar:
            all_members = tar.getmembers()
            # Check for unexpected native binaries
            for m in all_members:
                if m.isfile() and any(m.name.endswith(ext) for ext in NATIVE_BINARY_EXTENSIONS):
                    if not _is_test_or_fixture_path(m.name):
                        flag_by_key["BUNDLED_NATIVE_BINARY"] = f"BUNDLED_NATIVE_BINARY: Unexpected compiled binary '{m.name}' in npm tarball"
                        line_by_key["BUNDLED_NATIVE_BINARY"] = f"{m.name} -> unexpected native binary"

            # Check for weaponized binding.gyp (Shai-Hulud / node-gyp execution trap)
            for m in all_members:
                if m.isfile() and (m.name == "binding.gyp" or m.name.endswith("/binding.gyp")):
                    f_gyp = tar.extractfile(m)
                    if f_gyp:
                        gyp_content = f_gyp.read().decode("utf-8", errors="ignore")
                        for pat, label in GYP_WEAPONIZED_PATTERNS:
                            if pat.search(gyp_content):
                                key = f"GYP_WEAPONIZED_EXECUTION:{label}"
                                flag_by_key[key] = f"GYP_WEAPONIZED_EXECUTION: '{label}' detected in {m.name}"
                                line_by_key[key] = f"{m.name} -> {label} (node-gyp execution hook)"

            members = [m for m in all_members if m.isfile() and m.name.endswith(SOURCE_FILE_EXTENSIONS)]
            for member in members:
                if _is_test_or_fixture_path(member.name):
                    continue
                total_source_files += 1

                if files_scanned >= MAX_FILES_SCANNED or bytes_scanned >= MAX_TOTAL_BYTES_SCANNED:
                    continue  # keep counting files for size metrics, stop actively scanning content
                if member.size > MAX_BYTES_PER_FILE:
                    continue

                f = tar.extractfile(member)
                if not f:
                    continue
                raw = f.read()
                total_bytes += len(raw)
                content = raw.decode("utf-8", errors="ignore")
                total_loc += len([l for l in content.splitlines() if l.strip()])

                flags, lines = _scan_file_content(content, member.name)
                for key, text in flags:
                    occurrence_counts[key] = occurrence_counts.get(key, 0) + 1
                    flag_by_key.setdefault(key, text)
                for key, text in lines:
                    line_by_key.setdefault(key, text)

                files_scanned += 1
                bytes_scanned += len(raw)
    except Exception as e:
        return ASTSecurityReport(
            flags=[f"NPM_TARBALL_EXTRACTION_FAILED: {e}"],
            composite_threat_score=15,
            verdict=ThreatVerdict.SUSPICIOUS,
        )

    all_flags: List[str] = []
    for key, text in flag_by_key.items():
        count = occurrence_counts.get(key, 1)
        all_flags.append(f"{text} (+{count - 1} more occurrence(s) elsewhere)" if count > 1 else text)
    all_lines: List[str] = list(line_by_key.values())

    # Each distinct flag category contributes once
    threat_score = 0
    if any(f.startswith("CROSS_ECOSYSTEM_WORM_PROPAGATION") for f in all_flags):
        threat_score += 85
    if any(f.startswith("GYP_WEAPONIZED_EXECUTION") for f in all_flags):
        threat_score += 85
    if any(f.startswith("SOURCE_CODE_CONFIRMED_STEALER") for f in all_flags):
        threat_score += 80
    if any(f.startswith("SOURCE_CODE_DYNAMIC_CODE_LOADER") for f in all_flags):
        threat_score += 45
    if any(f.startswith("EXFILTRATION_DESTINATION_DETECTED") for f in all_flags):
        threat_score += 40
    if any(f.startswith("CREDENTIAL_PATH_HARVESTING") for f in all_flags):
        threat_score += 35
    if any(f.startswith("BUNDLED_NATIVE_BINARY") for f in all_flags):
        threat_score += 25
    if any(f.startswith("SOURCE_CODE_DYNAMIC_EXECUTION") for f in all_flags):
        threat_score += 25
    if any(f.startswith("SOURCE_CODE_ENCODED_PAYLOAD") for f in all_flags):
        threat_score += 15
    if any(f.startswith("SOURCE_CODE_ENV_VARS_ACCESS") for f in all_flags):
        threat_score += 15
    if any(f.startswith("SOURCE_CODE_NETWORK_CALL") for f in all_flags):
        threat_score += 10
    threat_score = min(100, threat_score)

    is_empty_stub = total_source_files == 0 and total_loc == 0
    size_tier = (
        "EMPTY_STUB" if is_empty_stub
        else "TINY_CODEBASE" if total_loc < 150
        else "MODERATE_CODEBASE" if total_loc < 1000
        else "LARGE_CODEBASE"
    )

    has_confirmed_weaponized_source = any(
        f.startswith((
            "CROSS_ECOSYSTEM_WORM_PROPAGATION",
            "GYP_WEAPONIZED_EXECUTION",
            "SOURCE_CODE_CONFIRMED_STEALER",
            "SOURCE_CODE_DYNAMIC_CODE_LOADER",
            "SOURCE_CODE_PERSISTENT_BACKDOOR",
            "SOURCE_CODE_EVASIVE_PAYLOAD",
        )) or "REVERSE_SHELL" in f
        for f in all_flags
    )

    verdict = ThreatVerdict.BENIGN_COMMUNITY
    if has_confirmed_weaponized_source:
        verdict = ThreatVerdict.MALICIOUS
    elif threat_score >= 35:
        verdict = ThreatVerdict.SUSPICIOUS

    return ASTSecurityReport(
        has_socket=any("SOURCE_CODE_NETWORK_CALL" in f for f in all_flags),
        has_exfiltration_destination=any("EXFILTRATION_DESTINATION_DETECTED" in f for f in all_flags),
        has_credential_harvesting=any("CREDENTIAL_PATH_HARVESTING" in f or "SOURCE_CODE_CONFIRMED_STEALER" in f for f in all_flags),
        has_bundled_binary=any("BUNDLED_NATIVE_BINARY" in f for f in all_flags),
        has_dynamic_obfuscation=any("DYNAMIC_EXECUTION" in f or "OBFUSCATION" in f for f in all_flags),
        total_source_files=total_source_files,
        total_lines_of_code=total_loc,
        total_code_size_bytes=total_bytes,
        is_empty_stub=is_empty_stub,
        code_size_tier=size_tier,
        flags=all_flags,
        line_details=all_lines,
        composite_threat_score=threat_score,
        verdict=verdict,
    )


def merge_ast_reports(manifest_report: ASTSecurityReport, source_report: ASTSecurityReport) -> ASTSecurityReport:
    """
    Combine the package.json-manifest-derived report (lifecycle scripts, declared
    metadata) with the tarball-source-derived report (actual JS/TS content) into
    one. Source-derived size metrics are preferred when available since they're
    real counts rather than the manifest's unpackedSize-based estimate.
    """
    has_real_source_metrics = source_report.total_source_files > 0

    verdict_rank = {
        ThreatVerdict.MALICIOUS: 4,
        ThreatVerdict.SUSPICIOUS: 3,
        ThreatVerdict.SQUATTED_STUB: 2,
        ThreatVerdict.BENIGN_COMMUNITY: 1,
        ThreatVerdict.VERIFIED_OFFICIAL: 0,
    }
    combined_verdict = max(manifest_report.verdict, source_report.verdict, key=lambda v: verdict_rank.get(v, 0))

    return ASTSecurityReport(
        has_socket=manifest_report.has_socket or source_report.has_socket,
        has_subprocess=manifest_report.has_subprocess or source_report.has_subprocess,
        has_os_system=manifest_report.has_os_system or source_report.has_os_system,
        has_base64_eval=manifest_report.has_base64_eval or source_report.has_base64_eval,
        has_lifecycle_scripts=manifest_report.has_lifecycle_scripts or source_report.has_lifecycle_scripts,
        has_pth_execution=manifest_report.has_pth_execution or source_report.has_pth_execution,
        has_exfiltration_destination=manifest_report.has_exfiltration_destination or source_report.has_exfiltration_destination,
        has_credential_harvesting=manifest_report.has_credential_harvesting or source_report.has_credential_harvesting,
        has_bundled_binary=manifest_report.has_bundled_binary or source_report.has_bundled_binary,
        has_dynamic_obfuscation=manifest_report.has_dynamic_obfuscation or source_report.has_dynamic_obfuscation,
        total_source_files=source_report.total_source_files if has_real_source_metrics else manifest_report.total_source_files,
        total_lines_of_code=source_report.total_lines_of_code if has_real_source_metrics else manifest_report.total_lines_of_code,
        total_code_size_bytes=source_report.total_code_size_bytes if has_real_source_metrics else manifest_report.total_code_size_bytes,
        is_empty_stub=manifest_report.is_empty_stub and source_report.is_empty_stub,
        code_size_tier=source_report.code_size_tier if has_real_source_metrics else manifest_report.code_size_tier,
        flags=manifest_report.flags + source_report.flags,
        line_details=manifest_report.line_details + source_report.line_details,
        composite_threat_score=min(100, manifest_report.composite_threat_score + source_report.composite_threat_score),
        verdict=combined_verdict,
    )
