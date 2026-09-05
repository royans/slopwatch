"""
SlopWatch — Unified Signal Model & Catalog.

This module is the single source of truth for *what a detection signal is*. Every
detector (``slopwatch.detectors``) and the progressive scorer emit ``Finding``
objects that reference a stable ``code`` defined in ``SIGNAL_CATALOG``.

Design goals:

1. **No schema change per signal.** A ``Finding`` is persisted as a row in the
   ``slopwatch_findings`` table keyed by its string ``code`` — adding a new signal
   never requires an ``ALTER TABLE`` or a new generated column. The web UI reads
   ``signal_catalog`` to render labels/badges dynamically.
2. **Facts vs. analysis stays explicit.** ``Finding.kind`` distinguishes an
   ``OBSERVATION`` (observable ground truth) from an ``ASSESSMENT``
   (heuristic interpretation) — the same separation the dossier exporter enforces.
3. **Backward compatibility.** ``findings_to_legacy_facets()`` projects a finding
   list back onto the flat ``ui_facets`` boolean keys the web
   frontend already consumes, so nothing downstream breaks on day one.

The catalog intentionally covers *every* flag string and ``EvidenceSignal`` id the
codebase emits today; ``tests/public/unit/test_signals.py`` enforces that the
scorer's code-execution/dangerous prefix tuples stay in sync with it.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ==================== Severity ====================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_RANK: Dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


def severity_rank(severity: str) -> int:
    """Numeric rank for range queries / ordering (unknown -> MEDIUM)."""
    return SEVERITY_RANK.get(str(severity).upper(), 2)


class FindingKind(str, Enum):
    OBSERVATION = "OBSERVATION"   # observable ground truth (a fact)
    ASSESSMENT = "ASSESSMENT"     # heuristic interpretation / scored judgement


# ==================== Signal Catalog ====================

# Coarse signal families. Mirrors Socket.dev's grouping (Supply Chain Risk /
# Malware / Provenance / Quality) so the UI sidebar can group facets.
class SignalCategory(str, Enum):
    MALWARE = "MALWARE"                    # confirmed weaponised behaviour
    CODE_EXECUTION = "CODE_EXECUTION"      # can run code at install/deploy time
    CODE_ANALYSIS = "CODE_ANALYSIS"       # static code pattern observations
    NAMING = "NAMING"                      # slopsquat / typosquat / grammar
    PROVENANCE = "PROVENANCE"              # publisher / vendor authenticity
    VERSIONING = "VERSIONING"              # dependency-confusion / inflated version
    TEMPORAL = "TEMPORAL"                  # dormancy / AI-era registration window
    PACKAGE_EFFORT = "PACKAGE_EFFORT"      # docs / codebase size / stub
    ADOPTION = "ADOPTION"                  # download volume / community usage
    MAINTENANCE = "MAINTENANCE"            # deprecation / abandonment
    INFRASTRUCTURE = "INFRASTRUCTURE"      # scan errors, unavailable metadata
    GENERAL = "GENERAL"


class SignalSpec(BaseModel):
    """One catalog entry — declarative metadata about a signal ``code``."""
    code: str
    title: str
    description: str = ""
    category: str = SignalCategory.GENERAL.value
    severity: str = Severity.MEDIUM.value
    default_score: int = 0
    kind: str = FindingKind.ASSESSMENT.value
    # UI hints (consumed by downstream web UI via ``signal_catalog``)
    ui_badge: Optional[str] = None
    ui_facet: Optional[str] = None          # legacy flat ui_facets.* key, if any
    # Behavioural classification (replaces scorer.py's prefix tuples)
    is_code_execution: bool = False         # -> has_install_hook family
    gates_malicious: bool = False           # a confirmed dangerous pattern
    doc_url: Optional[str] = None


def _spec(code: str, title: str, category: str, severity: str, **kw: Any) -> SignalSpec:
    return SignalSpec(code=code, title=title, category=category, severity=severity, **kw)


# Every entry below corresponds to a flag string or EvidenceSignal id the code
# emits today. Keep additions alphabetical within their block.
_CATALOG_ENTRIES: List[SignalSpec] = [
    # ---------- Confirmed malware / dangerous execution ----------
    _spec("INSTALL_TIME_EXECUTION", "Install-time code execution", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="⚡ Install Exec", ui_facet="has_install_hook",
          is_code_execution=True, gates_malicious=True,
          description="Top-level executable call runs automatically during package installation."),
    _spec("INSTALL_TIME_CMDCLASS_OVERRIDE", "Custom install command override", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="⚡ cmdclass Hook", ui_facet="has_install_hook",
          is_code_execution=True, gates_malicious=True,
          description="setup.py cmdclass overrides a build/install command to run code at install time."),
    _spec("INSTALL_TIME_NETWORK_SOCKET", "Install-time network socket", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=35, kind=FindingKind.OBSERVATION.value,
          ui_badge="🔌 Install Socket", ui_facet="has_network_socket",
          is_code_execution=True, gates_malicious=True,
          description="A raw network socket is opened during package installation."),
    _spec("OBFUSCATED_DYNAMIC_ACCESS", "Obfuscated dynamic call resolution", SignalCategory.MALWARE.value,
          Severity.HIGH.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="🕶️ Obfuscation", is_code_execution=True, gates_malicious=True,
          description="getattr/__import__/__dict__ used to resolve a dangerous call name dynamically."),
    _spec("PYTHON_PTH_CODE_EXECUTION", "Startup .pth code execution", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=85, kind=FindingKind.OBSERVATION.value,
          ui_badge="⚡ Startup .pth Hook", ui_facet="has_pth_execution",
          is_code_execution=True, gates_malicious=True,
          description="A .pth file executes code on every interpreter startup (Hades / LiteLLM pattern)."),
    _spec("SOURCE_CODE_CONFIRMED_STEALER", "Potential information stealer", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=80, kind=FindingKind.OBSERVATION.value,
          ui_badge="🚨 Potential Stealer", ui_facet="has_credential_harvesting",
          is_code_execution=True, gates_malicious=True,
          description="Possible exfiltration endpoint paired with credential or sensitive environment harvesting (unverified automated heuristic)."),
    _spec("SOURCE_CODE_PERSISTENT_BACKDOOR", "Persistent backdoor mechanism", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=85, kind=FindingKind.OBSERVATION.value,
          ui_badge="🚪 Persistent Backdoor", is_code_execution=True, gates_malicious=True,
          description="Persistence mechanism (cron/profile/registry) combined with execution or network call."),
    _spec("SOURCE_CODE_EVASIVE_PAYLOAD", "Evasive payload", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=80, kind=FindingKind.OBSERVATION.value,
          ui_badge="🛡️ Evasive Payload", is_code_execution=True, gates_malicious=True,
          description="Anti-analysis or CI sandbox evasion combined with execution or payload hook."),
    _spec("SYSTEM_PERSISTENCE_TAMPERING", "System persistence tampering", SignalCategory.CODE_EXECUTION.value,
          Severity.HIGH.value, default_score=40, kind=FindingKind.OBSERVATION.value,
          ui_badge="📌 Persistence Mechanism", is_code_execution=True,
          description="Cron job, shell profile, systemd unit, or Windows Run registry key tampering."),
    _spec("ANTI_ANALYSIS_EVASION", "Anti-analysis / sandbox evasion", SignalCategory.CODE_EXECUTION.value,
          Severity.MEDIUM.value, default_score=30, kind=FindingKind.OBSERVATION.value,
          ui_badge="🕵️ Anti-Analysis", is_code_execution=True,
          description="Probing CI environment, sandbox hostnames, or low hardware resource thresholds."),
    _spec("SUPPLY_CHAIN_EXECUTION_HOOK", "Supply-chain execution hook", SignalCategory.CODE_EXECUTION.value,
          Severity.HIGH.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="🪝 Supply-Chain Hook", is_code_execution=True,
          description="Dangerous npm lifecycle command, PyPI custom install class, or fileless memory execution."),
    _spec("SUSPICIOUS_OBFUSCATION", "Suspicious code obfuscation", SignalCategory.CODE_EXECUTION.value,
          Severity.MEDIUM.value, default_score=30, kind=FindingKind.OBSERVATION.value,
          ui_badge="🧩 Obfuscation", is_code_execution=True,
          description="Dense hex sequences, layered decode/decompress pipelines, or unicode steganography."),
    _spec("CROSS_ECOSYSTEM_WORM_PROPAGATION", "Cross-ecosystem propagation pattern", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=85, kind=FindingKind.OBSERVATION.value,
          ui_badge="🐛 Cross-Ecosystem Worm", is_code_execution=True, gates_malicious=True,
          description="Self-propagating worm logic probing registry upload endpoints / multi-ecosystem tokens."),
    _spec("GYP_WEAPONIZED_EXECUTION", "Suspicious binding.gyp execution hook", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=85, kind=FindingKind.OBSERVATION.value,
          ui_badge="⚙️ node-gyp Exec Trap", is_code_execution=True, gates_malicious=True,
          description="binding.gyp pattern with a potential Python sandbox escape or loose node invocation."),
    _spec("SOURCE_CODE_DYNAMIC_CODE_LOADER", "Dynamic code loader", SignalCategory.MALWARE.value,
          Severity.HIGH.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="⬇️ Code Loader", is_code_execution=True, gates_malicious=True,
          description="An execution primitive sits within 300 chars of a decode/network call (download-then-run)."),
    _spec("SUSPICIOUS_SHELL_COMMAND", "Suspicious shell command in lifecycle script", SignalCategory.MALWARE.value,
          Severity.HIGH.value, default_score=35, kind=FindingKind.OBSERVATION.value,
          ui_badge="🖥️ Shell Cradle", is_code_execution=True, gates_malicious=True,
          description="A lifecycle script contains curl|bash, node -e, certutil, nc -e or similar."),
    _spec("REVERSE_SHELL", "Reverse shell pattern", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="🐚 Reverse Shell", is_code_execution=True, gates_malicious=True,
          description="Socket + subprocess wiring characteristic of a reverse shell."),

    # ---------- Code execution capability (not necessarily malicious) ----------
    _spec("LIFECYCLE_SCRIPT", "Install script present", SignalCategory.CODE_EXECUTION.value,
          Severity.MEDIUM.value, default_score=25, kind=FindingKind.OBSERVATION.value,
          ui_badge="📜 Install Script", ui_facet="has_install_hook", is_code_execution=True,
          description="package.json declares a preinstall/install/postinstall lifecycle script."),
    _spec("PYTHON_PTH_STARTUP_HOOK", "Startup .pth file declared", SignalCategory.CODE_EXECUTION.value,
          Severity.MEDIUM.value, default_score=35, kind=FindingKind.OBSERVATION.value,
          ui_badge="📎 .pth File", ui_facet="has_pth_execution", is_code_execution=True,
          description="A .pth file is shipped in the distribution (executed at interpreter startup)."),
    _spec("CUSTOM_BUILD_BACKEND_UNVERIFIED", "Unverified custom build backend", SignalCategory.CODE_EXECUTION.value,
          Severity.MEDIUM.value, default_score=20, kind=FindingKind.OBSERVATION.value,
          ui_badge="🏗️ Custom Backend", is_code_execution=True,
          description="pyproject.toml declares a non-allowlisted PEP 517 build backend whose hooks run on install."),
    _spec("SOURCE_CODE_DYNAMIC_EXECUTION", "Dynamic code execution primitive", SignalCategory.CODE_ANALYSIS.value,
          Severity.MEDIUM.value, default_score=25, kind=FindingKind.OBSERVATION.value,
          ui_badge="🧬 eval / Function", description="eval(), new Function(), execSync or child_process found in source.",
          is_code_execution=True),
    _spec("SOURCE_CODE_ENCODED_PAYLOAD", "Encoded payload decode routine", SignalCategory.CODE_ANALYSIS.value,
          Severity.LOW.value, default_score=15, kind=FindingKind.OBSERVATION.value,
          ui_badge="🔐 base64 decode", description="Buffer.from(..., 'base64') / atob() decode routine found in source.",
          is_code_execution=True),
    _spec("SOURCE_CODE_NETWORK_CALL", "Network access in source", SignalCategory.CODE_ANALYSIS.value,
          Severity.LOW.value, default_score=10, kind=FindingKind.OBSERVATION.value,
          ui_badge="🌐 Network", ui_facet="has_network_socket",
          description="require('http(s)') / fetch / axios / XMLHttpRequest found in source."),
    _spec("SOURCE_CODE_ENV_VARS_ACCESS", "Environment variable access", SignalCategory.CODE_ANALYSIS.value,
          Severity.MEDIUM.value, default_score=15, kind=FindingKind.OBSERVATION.value,
          ui_badge="🔑 Env Vars Access", ui_facet="has_env_vars_access",
          description="process.env (JS) or os.environ / os.getenv (Python) accessed — possible credential stuffing.",
          is_code_execution=True),
    _spec("EXFILTRATION_DESTINATION_DETECTED", "C2 / exfiltration endpoint", SignalCategory.MALWARE.value,
          Severity.HIGH.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          ui_badge="📡 C2 / Webhook Exfil", ui_facet="has_exfiltration_destination",
          description="Outbound channel to a Discord/Telegram webhook, OAST domain, tunnel or raw public IP.",
          is_code_execution=True),
    _spec("CREDENTIAL_PATH_HARVESTING", "Credential store access", SignalCategory.MALWARE.value,
          Severity.HIGH.value, default_score=40, kind=FindingKind.OBSERVATION.value,
          ui_badge="🗄️ Credential Store Access", ui_facet="has_credential_harvesting",
          description="Reads ~/.aws, ~/.ssh, ~/.npmrc, ~/.kube, browser stores, IMDS 169.254.169.254 or k8s SA token.",
          is_code_execution=True),
    _spec("BUNDLED_NATIVE_BINARY", "Bundled native binary", SignalCategory.CODE_ANALYSIS.value,
          Severity.MEDIUM.value, default_score=25, kind=FindingKind.OBSERVATION.value,
          ui_badge="📦 Bundled Native Binary", ui_facet="has_bundled_binary",
          description="An unexpected compiled binary (.so/.dll/.dylib/.exe/.elf) is shipped in a script distribution.",
          is_code_execution=True),
    _spec("MISSING_SOURCE_REPOSITORY_URL", "Missing source repository URL", SignalCategory.PROVENANCE.value,
          Severity.LOW.value, default_score=15, kind=FindingKind.OBSERVATION.value,
          description="package.json declares no repository field."),

    # ---------- Naming heuristics ----------
    _spec("SIGNAL_COMBINATORIAL_GRAMMAR_MATCH", "AI hallucination grammar pattern", SignalCategory.NAMING.value,
          Severity.MEDIUM.value, default_score=25, ui_badge="🧩 Grammar Match",
          description="Name matches the [framework]-[entity]-[capability] template LLMs commonly hallucinate."),
    _spec("SIGNAL_HIGH_VALUE_BRAND_TARGET", "High-value brand target", SignalCategory.NAMING.value,
          Severity.HIGH.value, default_score=15, ui_badge="🎯 Brand Target",
          description="Name claims a critical enterprise / crypto / AI brand identity."),
    _spec("SIGNAL_INTERNAL_NAMESPACE_CONFUSION", "Internal namespace confusion keyword", SignalCategory.NAMING.value,
          Severity.MEDIUM.value, default_score=15, ui_badge="🏢 internal keyword",
          description="Name contains an 'internal' token — common in dependency-confusion attacks."),

    # ---------- Provenance / vendor authenticity ----------
    _spec("SIGNAL_OFFICIAL_VENDOR_DOMAIN_VERIFIED", "Official vendor domain verified", SignalCategory.PROVENANCE.value,
          Severity.INFO.value, default_score=-100, kind=FindingKind.OBSERVATION.value, ui_badge="✅ Verified Vendor",
          description="Author email belongs to an authorized official vendor domain."),
    _spec("SIGNAL_OFFICIAL_VENDOR_REPO_LINEAGE", "Official vendor repo lineage", SignalCategory.PROVENANCE.value,
          Severity.INFO.value, default_score=-40, kind=FindingKind.OBSERVATION.value, ui_badge="✅ Vendor Repo",
          description="Project homepage links to a verified vendor GitHub organization."),
    _spec("SIGNAL_ORGANIZATIONAL_DOMAIN_NAME_ALIGNMENT", "Organizational domain alignment", SignalCategory.PROVENANCE.value,
          Severity.INFO.value, default_score=-25, kind=FindingKind.OBSERVATION.value,
          description="Publisher email domain matches a package identifier token (identifiable third party)."),
    _spec("SIGNAL_UNVERIFIED_AUTHOR_DOMAIN", "Unverified author domain", SignalCategory.PROVENANCE.value,
          Severity.HIGH.value, default_score=25, ui_badge="⚠️ Unverified Publisher",
          description="Publisher email is not affiliated with the claimed brand's official vendor domain."),
    _spec("SIGNAL_URL_CONFUSION_HIJACKING", "Upstream repo URL hijacking", SignalCategory.PROVENANCE.value,
          Severity.HIGH.value, default_score=30, ui_badge="🔗 SourceRank Hijack",
          description="Package claims a legitimate high-profile upstream repository URL to inflate trust."),

    # ---------- Package effort ----------
    _spec("SIGNAL_HIGH_DOCUMENTATION_EFFORT", "Rich documentation effort", SignalCategory.PACKAGE_EFFORT.value,
          Severity.INFO.value, default_score=-15, kind=FindingKind.OBSERVATION.value,
          description="Substantial description plus a homepage link."),
    _spec("SIGNAL_EMPTY_OR_MINIMAL_DESCRIPTION", "Empty or minimal description", SignalCategory.PACKAGE_EFFORT.value,
          Severity.MEDIUM.value, default_score=15, kind=FindingKind.OBSERVATION.value,
          description="Near-zero description text (reservation stub indicator)."),
    _spec("SIGNAL_RAPID_SEMVER_BURST", "Rapid SemVer burst", SignalCategory.PACKAGE_EFFORT.value,
          Severity.MEDIUM.value, default_score=15, ui_badge="⏱️ Version Burst",
          description="Many versions published in rapid succession to mimic mature maintenance."),
    _spec("SIGNAL_EMPTY_CODE_STUB", "Empty code stub", SignalCategory.PACKAGE_EFFORT.value,
          Severity.MEDIUM.value, default_score=15, kind=FindingKind.OBSERVATION.value, ui_badge="🪹 Empty Stub",
          ui_facet="is_empty_stub", description="Package contains virtually no functional code (name-holding placeholder)."),
    _spec("SIGNAL_SUBSTANTIAL_CODEBASE", "Substantial codebase", SignalCategory.PACKAGE_EFFORT.value,
          Severity.INFO.value, default_score=-15, kind=FindingKind.OBSERVATION.value,
          description="A real functional codebase (>= 500 LOC)."),

    # ---------- Temporal ----------
    _spec("SIGNAL_AI_ERA_ACTIVE_REGISTRATION", "Registered in active AI-wave window", SignalCategory.TEMPORAL.value,
          Severity.HIGH.value, default_score=25, kind=FindingKind.OBSERVATION.value,
          description="Registered within the last 180 days during the active slopsquatting wave."),
    _spec("SIGNAL_AI_ERA_MODERATE_WINDOW", "Registered in AI proliferation window", SignalCategory.TEMPORAL.value,
          Severity.MEDIUM.value, default_score=15, kind=FindingKind.OBSERVATION.value,
          description="Registered 180-365 days ago within the AI-tool proliferation window."),
    _spec("SIGNAL_PRE_AI_HISTORICAL_PROJECT", "Pre-AI historical project", SignalCategory.TEMPORAL.value,
          Severity.INFO.value, default_score=-15, kind=FindingKind.OBSERVATION.value,
          description="Registered > 2 years ago, predating modern AI hallucination attacks."),

    # ---------- Versioning ----------
    _spec("SIGNAL_FUTURE_YEAR_VERSION_ANOMALY", "Future calendar-year version", SignalCategory.VERSIONING.value,
          Severity.HIGH.value, default_score=35, ui_badge="📅 Future Version",
          ui_facet="is_inflated_version", description="Major version is a suspicious future calendar year."),
    _spec("SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION", "Inflated major version", SignalCategory.VERSIONING.value,
          Severity.MEDIUM.value, default_score=25, ui_badge="⬆️ Inflated Version",
          ui_facet="is_inflated_version",
          description="Suspiciously high major version on a recently-registered package (dependency confusion)."),

    # ---------- Code analysis verdict signals ----------
    _spec("SIGNAL_WEAPONIZED_MALICIOUS_PAYLOAD", "Potential weaponized payload", SignalCategory.MALWARE.value,
          Severity.CRITICAL.value, default_score=45, kind=FindingKind.OBSERVATION.value,
          gates_malicious=True, is_code_execution=True,
          description="A suspicious install-time or source execution pattern was observed (unverified automated heuristic)."),
    _spec("SIGNAL_SUSPICIOUS_AST_PATTERN", "Suspicious AST pattern", SignalCategory.CODE_ANALYSIS.value,
          Severity.HIGH.value, default_score=25, kind=FindingKind.OBSERVATION.value,
          description="A suspicious but not individually conclusive code pattern was observed."),
    _spec("SIGNAL_AST_CODE_SAFE", "No malicious hooks detected", SignalCategory.CODE_ANALYSIS.value,
          Severity.INFO.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="No malicious install-time hooks or shell cradles detected in the package."),

    # ---------- Adoption ----------
    _spec("SIGNAL_HIGH_COMMUNITY_ADOPTION", "High community adoption", SignalCategory.ADOPTION.value,
          Severity.INFO.value, default_score=-40, kind=FindingKind.OBSERVATION.value,
          description=">= 10k monthly downloads — established community trust."),
    _spec("SIGNAL_ACTIVE_COMMUNITY_USAGE", "Active community usage", SignalCategory.ADOPTION.value,
          Severity.INFO.value, default_score=-20, kind=FindingKind.OBSERVATION.value,
          description=">= 1k monthly downloads."),
    _spec("SIGNAL_MODERATE_COMMUNITY_USAGE", "Moderate community usage", SignalCategory.ADOPTION.value,
          Severity.INFO.value, default_score=-10, kind=FindingKind.OBSERVATION.value,
          description=">= 100 monthly downloads."),

    # ---------- Maintenance ----------
    _spec("SIGNAL_REGISTRY_DEPRECATED", "Registry deprecation notice", SignalCategory.MAINTENANCE.value,
          Severity.INFO.value, default_score=-30, kind=FindingKind.OBSERVATION.value, ui_badge="ℹ️ Deprecated",
          ui_facet="is_deprecated", description="Officially deprecated or yanked by the upstream registry."),

    # ---------- Metadata heuristics (plugin detectors) ----------
    _spec("SUSPICIOUS_DESCRIPTION_LINK", "Suspicious link/text in description", SignalCategory.NAMING.value,
          Severity.MEDIUM.value, default_score=10, kind=FindingKind.OBSERVATION.value,
          ui_badge="🔗 Suspicious Description",
          description="Package description or homepage contains a chat-invite, URL shortener, "
                      "or crypto-airdrop lure commonly seen in throwaway malicious packages."),

    # ---------- Infrastructure / scan errors ----------
    _spec("SYNTAX_ERROR", "Source syntax error", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="A source file failed to parse during static inspection."),
    _spec("ARCHIVE_EXTRACTION_FAILED", "Archive extraction failed", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="The package archive could not be extracted for inspection."),
    _spec("NPM_TARBALL_EXTRACTION_FAILED", "npm tarball extraction failed", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="The npm tarball could not be extracted for inspection."),
    _spec("NPM_METADATA_UNAVAILABLE", "npm metadata unavailable", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="The npm registry returned no usable metadata for this package."),
    _spec("METADATA_UNAVAILABLE_OR_NO_SDIST", "No source distribution available", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="No inspectable sdist/wheel was published for this release."),
    _spec("TARBALL_DOWNLOAD_FAILED", "Tarball download failed", SignalCategory.INFRASTRUCTURE.value,
          Severity.LOW.value, default_score=0, kind=FindingKind.OBSERVATION.value,
          description="The release artifact could not be downloaded for inspection."),
]

SIGNAL_CATALOG: Dict[str, SignalSpec] = {s.code: s for s in _CATALOG_ENTRIES}

# Derived sets — replace scorer.py's hand-maintained prefix tuples. A contract
# test asserts the scorer's tuples are a subset of these.
CODE_EXECUTION_CODES = frozenset(c for c, s in SIGNAL_CATALOG.items() if s.is_code_execution)
CONFIRMED_DANGEROUS_CODES = frozenset(c for c, s in SIGNAL_CATALOG.items() if s.gates_malicious)


# ==================== Finding ====================

_CODE_HEAD_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def flag_code(flag: str) -> str:
    """
    Extract the stable signal ``code`` from a legacy flag string.

    Legacy flags look like ``"INSTALL_TIME_EXECUTION: 'exec' at top-level in setup.py:12"``
    or a bare ``"MISSING_SOURCE_REPOSITORY_URL"``. Per-file variants such as
    ``"SYNTAX_ERROR_IN_setup.py: ..."`` are normalised to their catalog code.
    """
    head = flag.split(":", 1)[0].strip()
    if head.startswith("SYNTAX_ERROR_IN_") or head.startswith("SYNTAX_ERROR_IN"):
        return "SYNTAX_ERROR"
    m = _CODE_HEAD_RE.match(head)
    return m.group(0) if m else head


class Finding(BaseModel):
    """A single detection signal instance emitted by a detector or the scorer."""
    code: str
    title: str = ""
    description: str = ""
    category: str = SignalCategory.GENERAL.value
    severity: str = Severity.MEDIUM.value
    score: int = 0
    confidence: float = 1.0
    kind: str = FindingKind.ASSESSMENT.value
    detector: str = "unknown"
    locations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_code_execution: bool = False
    gates_malicious: bool = False

    @property
    def severity_rank(self) -> int:
        return severity_rank(self.severity)

    # ---- constructors ----

    @classmethod
    def from_spec(cls, code: str, *, detector: str = "unknown", **overrides: Any) -> "Finding":
        spec = SIGNAL_CATALOG.get(code)
        if spec is None:
            base = dict(code=code, title=code.replace("_", " ").title())
        else:
            base = dict(
                code=code, title=spec.title, description=spec.description,
                category=spec.category, severity=spec.severity, score=spec.default_score,
                kind=spec.kind, is_code_execution=spec.is_code_execution,
                gates_malicious=spec.gates_malicious,
            )
        base["detector"] = detector
        base.update(overrides)
        return cls(**base)

    @classmethod
    def from_flag_string(cls, flag: str, *, detector: str = "assessor") -> "Finding":
        code = flag_code(flag)
        detail = flag.split(":", 1)[1].strip() if ":" in flag else flag
        spec = SIGNAL_CATALOG.get(code)
        # Legacy flags carry no score of their own (scorer already tallied the
        # points); keep score 0 for unknown/legacy codes so re-deriving findings
        # never changes an existing threat_score.
        f = cls.from_spec(code, detector=detector)
        if spec is None:
            f.category = SignalCategory.CODE_ANALYSIS.value
            f.severity = Severity.MEDIUM.value
        f.description = detail or f.description
        f.metadata.setdefault("raw_flag", flag)
        f.score = 0
        return f

    @classmethod
    def from_evidence_signal(cls, sig: Any, *, detector: str = "scorer") -> "Finding":
        code = getattr(sig, "signal_id", None) or getattr(sig, "code", None) or "SIGNAL_UNKNOWN"
        spec = SIGNAL_CATALOG.get(code)
        return cls(
            code=code,
            title=spec.title if spec else code.replace("SIGNAL_", "").replace("_", " ").title(),
            description=getattr(sig, "human_description", "") or (spec.description if spec else ""),
            category=spec.category if spec else getattr(sig, "category", SignalCategory.GENERAL.value),
            severity=getattr(sig, "severity", None) or (spec.severity if spec else Severity.MEDIUM.value),
            score=int(getattr(sig, "score_impact", 0) or 0),
            kind=(spec.kind if spec else FindingKind.ASSESSMENT.value),
            detector=detector,
            metadata=dict(getattr(sig, "metadata", {}) or {}),
            is_code_execution=spec.is_code_execution if spec else False,
            gates_malicious=(spec.gates_malicious if spec else False) or bool(getattr(sig, "is_critical", False)),
        )

    def to_evidence_signal(self) -> Any:
        """Convert back to an ``EvidenceSignal`` for the scorer's existing flow."""
        from slopwatch.core.dto import EvidenceSignal
        return EvidenceSignal(
            signal_id=self.code,
            category=self.category,
            severity=self.severity,
            score_impact=self.score,
            rule_code=f"RULE_{self.code}",
            human_description=self.description or self.title,
            metadata=self.metadata,
            is_critical=self.gates_malicious,
        )


# ==================== Aggregation helpers ====================

def evidence_signals_to_findings(signals: List[Any], *, detector: str = "scorer") -> List[Finding]:
    return [Finding.from_evidence_signal(s, detector=detector) for s in signals]


def flags_to_findings(flags: List[str], *, detector: str = "assessor") -> List[Finding]:
    out: List[Finding] = []
    for flag in flags or []:
        if not isinstance(flag, str) or not flag.strip():
            continue
        out.append(Finding.from_flag_string(flag, detector=detector))
    return out


def build_findings(
    evidence_signals: Optional[List[Any]] = None,
    ast_flags: Optional[List[str]] = None,
    extra_findings: Optional[List[Finding]] = None,
) -> List[Finding]:
    """
    Merge the scorer's structured ``EvidenceSignal`` list, the raw AST flag
    strings, and any plugin-detector findings into one de-duplicated list
    (keyed by ``code`` — first occurrence wins, so structured signals with real
    scores take precedence over the flag-string re-derivation).
    """
    by_code: Dict[str, Finding] = {}
    for f in evidence_signals_to_findings(evidence_signals or []):
        by_code.setdefault(f.code, f)
    for f in extra_findings or []:
        by_code.setdefault(f.code, f)
    for f in flags_to_findings(ast_flags or []):
        by_code.setdefault(f.code, f)
    return list(by_code.values())


# Legacy flat ``ui_facets`` boolean keys the web frontend reads.
# Derived from the catalog's ``ui_facet`` field plus a couple of computed ones.
_LEGACY_FACET_CODES: Dict[str, List[str]] = {}
for _c, _s in SIGNAL_CATALOG.items():
    if _s.ui_facet:
        _LEGACY_FACET_CODES.setdefault(_s.ui_facet, []).append(_c)


def findings_to_legacy_facets(findings: List[Finding]) -> Dict[str, bool]:
    """Project a finding list onto the flat ``ui_facets.has_*`` booleans."""
    present = {f.code for f in findings}
    facets: Dict[str, bool] = {
        facet: any(c in present for c in codes)
        for facet, codes in _LEGACY_FACET_CODES.items()
    }
    # Computed composites kept for backward compatibility.
    facets["has_install_hook"] = any(
        SIGNAL_CATALOG.get(c, SignalSpec(code=c, title=c, category="", severity="")).is_code_execution
        for c in present
    )
    facets["has_network_socket"] = any(
        "SOCKET" in c or "NETWORK" in c for c in present
    )
    facets["has_confirmed_dangerous_execution"] = any(
        SIGNAL_CATALOG.get(c, SignalSpec(code=c, title=c, category="", severity="")).gates_malicious
        for c in present
    )
    return facets


def findings_from_analysis_details(details: Optional[Dict[str, Any]]) -> List[Finding]:
    """
    Rebuild a ``Finding`` list from a persisted ``analysis_details`` blob.

    Prefers a stored ``findings`` array (written by the current scorer); falls
    back to re-deriving from the legacy ``signals`` + ``flags`` shape so historic
    rows light up the findings table without a re-crawl.
    """
    details = details or {}
    raw = details.get("findings")
    if isinstance(raw, list) and raw:
        out: List[Finding] = []
        for item in raw:
            try:
                out.append(item if isinstance(item, Finding) else Finding(**item))
            except Exception:
                continue
        if out:
            return out

    from slopwatch.core.dto import EvidenceSignal

    ev: List[Any] = []
    for s in details.get("signals", []) or []:
        if isinstance(s, EvidenceSignal):
            ev.append(s)
        elif isinstance(s, dict):
            try:
                ev.append(EvidenceSignal(**s))
            except Exception:
                continue
    return build_findings(ev, details.get("flags", []))


def catalog_as_rows() -> List[Dict[str, Any]]:
    """Serialised catalog for ``signal_catalog`` / static export."""
    return [
        {
            "signal_code": s.code,
            "title": s.title,
            "description": s.description,
            "category": s.category,
            "severity": s.severity,
            "severity_rank": severity_rank(s.severity),
            "default_score": s.default_score,
            "kind": s.kind,
            "ui_badge": s.ui_badge,
            "ui_facet": s.ui_facet,
            "is_code_execution": s.is_code_execution,
            "gates_malicious": s.gates_malicious,
        }
        for s in sorted(SIGNAL_CATALOG.values(), key=lambda x: (x.category, x.code))
    ]
