"""
Progressive Multi-Tier Threat Evaluator & Point-Based Risk Scorer.

Evaluates package risks across an explicit, additive point rubric:
1. Combinatorial AI Grammar & High-Value Brand (+25 to +40 pts)
2. Publisher Domain Authenticity (-100 pts for official, +25 pts for unverified)
3. Package Structural Effort (-15 pts for rich docs, +15 pts for stub)
4. Dormant Sleeper-Squatting Age Tracking (+10 to +20 pts based on dormancy)
5. Install-Time AST Weaponization & Network Hooks (+25 to +45 pts for malware)
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel

from sentinel.core.dto import (
    WatchlistCandidate,
    SquatDetection,
    ThreatVerdict,
    EvidenceSignal,
    Ecosystem,
)
from sentinel.core.taxonomies import (
    VENDOR_DOMAINS,
    PUBLIC_EMAIL_PROVIDERS,
    DISPOSABLE_EMAIL_DOMAINS,
)
from sentinel.core.signals import build_findings

# High-Value Enterprise, AI & Crypto Brands (Highest target value for adversaries)
HIGH_VALUE_BRANDS: Set[str] = {
    # 🚨 Top Crypto Companies, Exchanges, Wallets, Chains & DeFi
    "bitcoin", "btc", "ethereum", "eth", "solana", "sol", "metamask", "binance",
    "coinbase", "kraken", "okx", "bybit", "kucoin", "bitfinex", "crypto-com", "cryptocom",
    "gemini", "gateio", "deribit", "bitget", "mexc", "robinhood", "bitstamp",
    "ledger", "trezor", "phantom", "trustwallet", "exodus", "keplr", "rabby",
    "rainbow", "safe", "gnosis-safe", "argent", "zerion", "walletconnect",
    "web3", "ethers", "ethersproject", "viem", "wagmi", "foundry", "hardhat",
    "alchemy", "infura", "quicknode", "moralis", "thegraph", "graphprotocol",
    "chainlink", "pyth", "wormhole", "layerzero", "axelar",
    "polygon", "matic", "arbitrum", "optimism", "base", "zksync", "starknet",
    "scroll", "linea", "mantle", "berachain", "celestia", "sei", "injective",
    "avalanche", "avax", "cardano", "ada", "polkadot", "dot", "cosmos", "atom",
    "near", "aptos", "sui", "ton", "toncoin", "ripple", "xrp", "tron", "trx", "monero", "xmr",
    "uniswap", "aave", "compound", "curve", "curvefi", "makerdao", "maker", "lido",
    "pancakeswap", "sushiswap", "balancer", "synthetix", "dydx", "1inch", "yearn",
    "gmx", "jupiter", "raydium", "hyperliquid", "morpho", "eigenlayer", "ethena", "pendle",
    "opensea", "blur", "magic-eden", "tether", "usdt", "circle", "usdc", "paxos",

    # Top AI Companies, Labs & Frameworks
    "openai", "anthropic", "claude", "deepseek", "deepseek-ai", "mistral", "mistralai",
    "cohere", "gemini", "deepmind", "meta-llama", "llama", "groq", "huggingface", "hf",
    "langchain", "langgraph", "langsmith", "llamaindex", "crewai", "vllm", "ollama",
    "perplexity", "xai", "grok", "together", "replicate", "elevenlabs", "stability",
    "cursor", "copilot", "pinecone", "weaviate", "qdrant", "chroma", "chromadb",

    # Core Cloud, Identity & Billing Platforms
    "google", "google-cloud", "gcp", "microsoft", "azure", "aws", "amazon",
    "okta", "auth0", "clerk", "supabase", "snowflake", "stripe", "cloudflare", "github",
    "keycloak", "duo",
}

# Official Vendor GitHub Organizations
OFFICIAL_VENDOR_ORGS: Dict[str, List[str]] = {
    # Crypto & Web3
    "bitcoin": ["github.com/bitcoin", "github.com/bitcoincore"],
    "btc": ["github.com/bitcoin", "github.com/bitcoincore"],
    "ethereum": ["github.com/ethereum"],
    "solana": ["github.com/solana-labs", "github.com/solana-foundation"],
    "metamask": ["github.com/metamask", "github.com/consensys"],
    "coinbase": ["github.com/coinbase"],
    "binance": ["github.com/binance"],
    "ledger": ["github.com/ledgerhq"],
    "trezor": ["github.com/trezor", "github.com/satoshilabs"],
    "uniswap": ["github.com/uniswap"],
    "aave": ["github.com/aave"],
    "chainlink": ["github.com/smartcontractkit"],
    "polygon": ["github.com/maticnetwork", "github.com/0xpolygon"],
    "arbitrum": ["github.com/offchainlabs"],
    "safe": ["github.com/safe-global"],
    "walletconnect": ["github.com/walletconnect"],
    # AI & Cloud
    "google": ["github.com/google", "github.com/googleapis", "github.com/googlecloudplatform"],
    "google-cloud": ["github.com/google", "github.com/googleapis", "github.com/googlecloudplatform"],
    "gcp": ["github.com/google", "github.com/googleapis", "github.com/googlecloudplatform"],
    "microsoft": ["github.com/microsoft", "github.com/azure"],
    "azure": ["github.com/azure", "github.com/microsoft"],
    "aws": ["github.com/aws", "github.com/awslabs", "github.com/boto"],
    "amazon": ["github.com/aws", "github.com/amazon"],
    "okta": ["github.com/okta", "github.com/oktadev"],
    "auth0": ["github.com/auth0"],
    "clerk": ["github.com/clerk"],
    "supabase": ["github.com/supabase"],
    "snowflake": ["github.com/snowflakedb"],
    "stripe": ["github.com/stripe"],
    "openai": ["github.com/openai"],
    "anthropic": ["github.com/anthropics"],
    "deepseek": ["github.com/deepseek-ai"],
    "mistral": ["github.com/mistralai"],
    "cohere": ["github.com/cohere-ai"],
    "huggingface": ["github.com/huggingface"],
    "langchain": ["github.com/langchain-ai"],
    "llamaindex": ["github.com/run-llama"],
    "crewai": ["github.com/crewaiinc", "github.com/joaomdmoura/crewai"],
    "vllm": ["github.com/vllm-project"],
    "ollama": ["github.com/ollama"],
    "groq": ["github.com/groq"],
    "pinecone": ["github.com/pinecone-io"],
    "weaviate": ["github.com/weaviate"],
    "qdrant": ["github.com/qdrant"],
    "chroma": ["github.com/chroma-core"],
    "chromadb": ["github.com/chroma-core"],
    "keycloak": ["github.com/keycloak"],
    "duo": ["github.com/duosecurity"],
    "shopify": ["github.com/shopify"],
    "slack": ["github.com/slackapi"],
}

# High-Profile Official Upstream Repositories (Monitored for URL Confusion & SourceRank Hijacking)
HIGH_PROFILE_OFFICIAL_REPOS: Dict[str, str] = {
    "psf/requests": "requests",
    "pandas-dev/pandas": "pandas",
    "numpy/numpy": "numpy",
    "pallets/flask": "flask",
    "tiangolo/fastapi": "fastapi",
    "django/django": "django",
    "openai/openai-python": "openai",
    "anthropics/anthropic-sdk-python": "anthropic",
    "pydantic/pydantic": "pydantic",
    "psf/black": "black",
    "pytest-dev/pytest": "pytest",
    "encode/httpx": "httpx",
    "langchain-ai/langchain": "langchain",
    "run-llama/llama_index": "llama-index",
    "docker/docker-py": "docker",
    "boto/boto3": "boto3",
    "ansible/ansible": "ansible",
    "aio-libs/aiohttp": "aiohttp",
    "urllib3/urllib3": "urllib3",
    "scikit-learn/scikit-learn": "scikit-learn",
    "tensorflow/tensorflow": "tensorflow",
    "pytorch/pytorch": "torch",
    "bitcoin/bitcoin": "bitcoin",
    "ethereum/go-ethereum": "ethereum",
    "solana-labs/solana": "solana",
}


# ==================== Install-Time Code Execution Classification ====================
# Flag prefixes emitted by the AST/manifest inspectors (sentinel.assessor.python_ast,
# sentinel.assessor.npm_manifest) that indicate the package CAN execute arbitrary code
# automatically as part of installation/deployment — as opposed to purely informational
# flags (missing repo URL, archive/parse failures) which carry no execution risk.
CODE_EXECUTION_FLAG_PREFIXES = (
    "INSTALL_TIME_EXECUTION",
    "INSTALL_TIME_CMDCLASS_OVERRIDE",
    "INSTALL_TIME_NETWORK_SOCKET",
    "OBFUSCATED_DYNAMIC_ACCESS",
    "LIFECYCLE_SCRIPT",
    "PYTHON_PTH_CODE_EXECUTION",
    "PYTHON_PTH_STARTUP_HOOK",
    "SOURCE_CODE_CONFIRMED_STEALER",
    "SOURCE_CODE_PERSISTENT_BACKDOOR",  # persistence primitive + execution/network
    "SOURCE_CODE_EVASIVE_PAYLOAD",      # anti-analysis evasion + payload/hook
    "SYSTEM_PERSISTENCE_TAMPERING",     # cron, shell profile, systemd, registry run keys
    "ANTI_ANALYSIS_EVASION",            # CI/sandbox detection, hostname profiling, stalls
    "SUPPLY_CHAIN_EXECUTION_HOOK",      # lifecycle command, cmdclass override, .pth execution
    "SUSPICIOUS_OBFUSCATION",           # dense hex, layered decode/decompress, steganography
    "CROSS_ECOSYSTEM_WORM_PROPAGATION",  # worm replication: probing upload.pypi.org, multi-token handling
    "GYP_WEAPONIZED_EXECUTION",          # node-gyp: python sandbox escape or command execution in binding.gyp
    "SOURCE_CODE_DYNAMIC_EXECUTION",     # npm: eval/Function()/child_process/execSync found in real tarball source
    "SOURCE_CODE_ENCODED_PAYLOAD",       # npm: base64/atob decode routine found in real tarball source
    "SOURCE_CODE_DYNAMIC_CODE_LOADER",   # npm: execution primitive + decode/network in the same source file
    "SOURCE_CODE_ENV_VARS_ACCESS",       # npm/pypi: process.env or os.environ credential harvesting
    "EXFILTRATION_DESTINATION_DETECTED", # c2/webhook endpoints (Discord, Telegram, OAST, IPs)
    "CREDENTIAL_PATH_HARVESTING",        # reading ~/.aws, ~/.ssh, ~/.npmrc, browser data, IMDS
    "BUNDLED_NATIVE_BINARY",             # unexpected native compiled binary in archive
    "CUSTOM_BUILD_BACKEND_UNVERIFIED",   # pypi: pyproject.toml declares a non-allowlisted build backend
)

# A stricter subset confirming a specific dangerous pattern was actually observed
# (not just "an install hook exists"). Gates the MALICIOUS verdict; a plain npm
# postinstall script (e.g. rebuilding a native binding) alone should not.
CONFIRMED_DANGEROUS_FLAG_PREFIXES = (
    "INSTALL_TIME_EXECUTION",
    "INSTALL_TIME_CMDCLASS_OVERRIDE",
    "INSTALL_TIME_NETWORK_SOCKET",
    "OBFUSCATED_DYNAMIC_ACCESS",
    "SUSPICIOUS_SHELL_COMMAND",  # npm: a dangerous pattern (curl|bash, etc.) matched inside a lifecycle script
    "SOURCE_CODE_DYNAMIC_CODE_LOADER",  # npm: the "download/decode then execute" shape in real tarball source
    "SOURCE_CODE_CONFIRMED_STEALER",    # npm/pypi: exfiltration endpoint combined with secret access
    "SOURCE_CODE_PERSISTENT_BACKDOOR",  # persistence primitive + execution/network
    "SOURCE_CODE_EVASIVE_PAYLOAD",      # anti-analysis evasion + execution/payload hook
    "PYTHON_PTH_CODE_EXECUTION",        # pypi: dangerous startup code in .pth file
    "GYP_WEAPONIZED_EXECUTION",         # npm: malicious node-gyp python escape or node execution
    "CROSS_ECOSYSTEM_WORM_PROPAGATION", # npm/pypi: self-replicating worm logic
)


def has_install_time_code_execution(flags: List[str]) -> bool:
    """
    Broad, UI-filterable "can this package run code on install/deploy?" signal — any
    top-level install-time exec, cmdclass override, install-time network socket,
    dynamic-obfuscation access, or npm lifecycle script, regardless of whether a
    specific dangerous shell pattern was matched inside it. Populates the
    `has_install_hook` field synced to downstream indexed column.
    """
    return any(f.startswith(CODE_EXECUTION_FLAG_PREFIXES) for f in flags)


def has_confirmed_dangerous_execution(flags: List[str]) -> bool:
    """
    Narrower than has_install_time_code_execution(): true only when a specific
    dangerous pattern was actually observed. This is what gates the MALICIOUS
    verdict.
    """
    if any(f.startswith(CONFIRMED_DANGEROUS_FLAG_PREFIXES) for f in flags):
        return True

    # Check for exfiltration destination + credential or environment harvesting
    has_exfil = any(f.startswith("EXFILTRATION_DESTINATION_DETECTED") for f in flags)
    has_cred = any(f.startswith("CREDENTIAL_PATH_HARVESTING") for f in flags)
    has_env = any(f.startswith("SOURCE_CODE_ENV_VARS_ACCESS") for f in flags)

    if has_exfil and (has_cred or has_env):
        return True

    return False


def has_install_time_network_socket(flags: List[str]) -> bool:
    """True if a network socket call was observed specifically during install (Python only)."""
    return any("SOCKET" in f for f in flags)


def is_date_stamp_version(major_version: int, current_year: int) -> bool:
    """
    Detect YYYYMM / YYYYMMDD date-stamp version schemes (e.g. 202605 = 2026-05,
    20260514 = 2026-05-14) some projects use for CalVer-style or build-date-derived
    releases. Without this, a legitimate date-stamped version gets misclassified as
    an "inflated major version" dependency-confusion signal — confirmed in production
    (powerline-claude-code v202605.0, nano-vllm-fork v20260210).
    """
    s = str(major_version)
    if len(s) not in (6, 8):
        return False
    try:
        year = int(s[:4])
        month = int(s[4:6])
        if not (1990 <= year <= current_year + 1 and 1 <= month <= 12):
            return False
        if len(s) == 8:
            day = int(s[6:8])
            if not (1 <= day <= 31):
                return False
        return True
    except ValueError:
        return False


class ProgressiveThreatEvaluator:
    def __init__(
        self,
        concurrency_limit: int = 10,
        global_timeout_seconds: float = 300.0,
        detection_engine=None,
    ):
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.global_timeout_seconds = global_timeout_seconds
        # Plugin detector engine (sentinel.detectors). Lazily resolved to the
        # process-wide shared engine on first use so detector discovery only
        # happens once per process. Injectable for tests.
        self._detection_engine = detection_engine

    def _get_engine(self):
        if self._detection_engine is None:
            from sentinel.detectors.engine import get_shared_engine
            self._detection_engine = get_shared_engine()
        return self._detection_engine

    async def _run_plugin_detectors(
        self,
        *,
        candidate: "WatchlistCandidate",
        pkg_name: str,
        meta=None,
        ast_report=None,
        existing_signals=None,
    ):
        """Run pluggable detectors; failures degrade to an empty list."""
        try:
            from sentinel.detectors.base import PackageContext
            ctx = PackageContext(
                ecosystem=candidate.ecosystem,
                package_name=pkg_name,
                candidate=candidate,
                metadata=meta,
                ast_report=ast_report,
                existing_signals=list(existing_signals or []),
            )
            return await self._get_engine().run(ctx)
        except Exception:
            return []

    def verify_vendor_ownership(self, entity_token: str, author_email: Optional[str]) -> bool:
        """Verify if author email belongs to official vendor domain."""
        if not author_email:
            return False
        from sentinel.core.normalizers import extract_clean_email_and_domain
        _, clean_domain = extract_clean_email_and_domain(author_email)
        if not clean_domain:
            return False
        entity_key = entity_token.lower()
        if entity_key in VENDOR_DOMAINS:
            for domain in VENDOR_DOMAINS[entity_key]:
                if clean_domain == domain or clean_domain.endswith(f".{domain}"):
                    return True
        return False

    def verify_vendor_repo_lineage(self, entity_token: str, homepage_or_url: Optional[str]) -> bool:
        """Check if project repository belongs to verified vendor GitHub organization."""
        if not homepage_or_url:
            return False
        url_lower = homepage_or_url.lower().strip()
        entity_key = entity_token.lower()
        if entity_key in OFFICIAL_VENDOR_ORGS:
            for org in OFFICIAL_VENDOR_ORGS[entity_key]:
                if org in url_lower:
                    return True
        return False

    def check_url_confusion_hijacking(
        self,
        package_name: str,
        homepage: Optional[str],
        project_urls: Dict[str, str],
        is_vendor_domain: bool,
    ) -> Optional[tuple[str, str]]:
        """
        Detect if a package claims the repository URL of a legitimate high-profile package to hijack SourceRank / trust.
        Returns (claimed_repo, official_pkg_name) if hijacking is detected.
        """
        if is_vendor_domain:
            return None
        urls_to_check = []
        if homepage:
            urls_to_check.append(homepage.lower())
        if project_urls:
            for u in project_urls.values():
                if isinstance(u, str):
                    urls_to_check.append(u.lower())

        pkg_norm = package_name.lower().replace("_", "-")

        for claimed_repo, official_pkg in HIGH_PROFILE_OFFICIAL_REPOS.items():
            for u in urls_to_check:
                if f"github.com/{claimed_repo}" in u or f"gitlab.com/{claimed_repo}" in u:
                    if pkg_norm != official_pkg and not pkg_norm.startswith(f"{official_pkg}-core"):
                        return claimed_repo, official_pkg
        return None

    def calculate_dormancy_signals(self, published_at: Optional[datetime]) -> tuple[int, Optional[EvidenceSignal], int]:
        """
        Temporal Risk & AI Era Window Scoring:
        - Recent / AI-Wave Window (< 180 days): +25 pts (Prime window for active AI hallucination slopsquatting).
        - AI-Era Window (180 - 365 days): +15 pts (Registered during AI assistant proliferation wave).
        - Transitional Project (365 - 730 days): 0 pts (Neutral pre-AI timeline).
        - Established Mature / Pre-AI Era (> 730 days): -15 pts (Historical open-source library predating AI hallucination attacks).
        Returns: (points, signal, days_dormant)
        """
        if not published_at:
            return 0, None, 0

        now = datetime.now(timezone.utc)
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)

        days_dormant = max(0, (now - published_at).days)

        if days_dormant <= 180:
            # Active AI hallucination wave window
            sig = EvidenceSignal(
                signal_id="SIGNAL_AI_ERA_ACTIVE_REGISTRATION",
                category="TEMPORAL_DORMANCY",
                severity="HIGH",
                score_impact=25,
                rule_code="RULE_AI_ERA_RECENT_REGISTRATION",
                human_description=f"Package registered recently ({days_dormant} days ago) during the active AI hallucination slopsquatting wave.",
                metadata={"days_dormant": days_dormant, "ai_era_window": "ACTIVE_AI_WAVE"},
            )
            return 25, sig, days_dormant
        elif days_dormant <= 365:
            # Within 1 year AI tool proliferation window
            sig = EvidenceSignal(
                signal_id="SIGNAL_AI_ERA_MODERATE_WINDOW",
                category="TEMPORAL_DORMANCY",
                severity="MEDIUM",
                score_impact=15,
                rule_code="RULE_AI_ERA_1YR_WINDOW",
                human_description=f"Package registered {days_dormant} days ago within the 1-year AI tool proliferation window.",
                metadata={"days_dormant": days_dormant, "ai_era_window": "PROLIFERATION_WINDOW"},
            )
            return 15, sig, days_dormant
        elif days_dormant > 730:
            # Over 2 years old: Established pre-AI open source project
            sig = EvidenceSignal(
                signal_id="SIGNAL_PRE_AI_HISTORICAL_PROJECT",
                category="TEMPORAL_DORMANCY",
                severity="INFO",
                score_impact=-15,
                rule_code="RULE_PRE_AI_HISTORICAL_PACKAGE",
                human_description=f"Established pre-AI legacy package registered {days_dormant} days ago (predates modern AI hallucination waves).",
                metadata={"days_dormant": days_dormant, "ai_era_window": "PRE_AI_HISTORICAL"},
            )
            return -15, sig, days_dormant
        else:
            # 1 to 2 years old: transitional
            return 0, None, days_dormant

    @staticmethod
    def extract_major_version(version_str: Optional[str]) -> int:
        """Extract integer major version number from a SemVer or release string."""
        if not version_str:
            return 0
        import re
        cleaned = re.sub(r"^[^\d]+", "", str(version_str).strip())
        match = re.match(r"^(\d+)", cleaned)
        if match:
            try:
                return int(match.group(1))
            except (ValueError, TypeError):
                return 0
        return 0

    async def evaluate_candidate(
        self,
        candidate: WatchlistCandidate,
        version: Optional[str] = None,
    ) -> SquatDetection:
        """
        Run progressive additive point-based threat investigation on a candidate.
        """
        async with self.semaphore:
            from sentinel.adapters import get_adapter

            ecosystem = candidate.ecosystem
            pkg_name = candidate.normalized_name
            adapter = get_adapter(ecosystem)

            evidence_signals: List[EvidenceSignal] = []
            accumulated_score = 0

            # ==================== 1. NAMING & AI GRAMMAR RUBRIC (+25 to +40 pts) ====================
            is_known_brand = (
                candidate.entity_token.lower() in HIGH_VALUE_BRANDS
                or candidate.entity_token.lower() in VENDOR_DOMAINS
            )

            if is_known_brand:
                accumulated_score += 25
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_COMBINATORIAL_GRAMMAR_MATCH",
                        category="NAMING_HEURISTIC",
                        severity="MEDIUM",
                        score_impact=25,
                        rule_code="RULE_GRAMMAR_TRIPLET_MATCH",
                        human_description=f"Package name '{pkg_name}' matches AI hallucination template [{candidate.framework_token}] + [{candidate.entity_token}] + [{candidate.capability_token}].",
                        metadata={
                            "template": "{framework}-{entity}-{capability}",
                            "framework": candidate.framework_token,
                            "entity": candidate.entity_token,
                            "capability": candidate.capability_token,
                        },
                    )
                )
                accumulated_score += 15
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_HIGH_VALUE_BRAND_TARGET",
                        category="NAMING_HEURISTIC",
                        severity="HIGH",
                        score_impact=15,
                        rule_code="RULE_HIGH_VALUE_BRAND",
                        human_description=f"Claims critical enterprise brand identity ('{candidate.entity_token.upper()}').",
                        metadata={"brand": candidate.entity_token},
                    )
                )

            # ==================== 2. METADATA & VENDOR PROOF RUBRIC ====================
            meta = await adapter.inspect_package_metadata(pkg_name)
            if not meta:
                # Unregistered candidate on watchlist
                return SquatDetection(
                    candidate_id=candidate.candidate_id,
                    ecosystem=ecosystem,
                    package_name=pkg_name,
                    threat_score=candidate.risk_weight,
                    analysis_details={
                        "verdict_reason": "UNREGISTERED_WATCHLIST_TARGET",
                        "entity": candidate.entity_token,
                        "capability": candidate.capability_token,
                        "framework": candidate.framework_token,
                        "signals": [s.model_dump() for s in evidence_signals],
                        "findings": [
                            f.model_dump(mode="json")
                            for f in build_findings(evidence_signals, [])
                        ],
                        # No payload was ever inspected (not registered) — nothing to flag.
                        "has_install_hook": False,
                        "has_network_socket": False,
                        "has_confirmed_dangerous_execution": False,
                    },
                    verdict=ThreatVerdict.SUSPICIOUS if candidate.risk_weight >= 60 else ThreatVerdict.BENIGN_COMMUNITY,
                )

            # Check Official Vendor Domain Proof vs Organizational Domain Alignment
            is_vendor_domain = self.verify_vendor_ownership(candidate.entity_token, meta.author_email)
            is_vendor_repo = self.verify_vendor_repo_lineage(candidate.entity_token, meta.homepage)

            from sentinel.core.normalizers import extract_clean_email_and_domain
            clean_author_email, author_domain = extract_clean_email_and_domain(meta.author_email)
            domain_root = author_domain.split(".")[0].lower() if author_domain and "." in author_domain else (author_domain.lower() if author_domain else "")
            is_generic_esp = bool(author_domain and (author_domain.lower() in PUBLIC_EMAIL_PROVIDERS or author_domain.lower() in DISPOSABLE_EMAIL_DOMAINS))

            pkg_tokens = [t.lower() for t in pkg_name.replace("_", "-").split("-")]
            is_domain_aligned = bool(
                author_domain
                and not is_generic_esp
                and len(domain_root) >= 3
                and (domain_root in pkg_tokens or any(t.startswith(domain_root) or domain_root.startswith(t) for t in pkg_tokens if len(t) >= 4))
            )

            if is_vendor_domain:
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_OFFICIAL_VENDOR_DOMAIN_VERIFIED",
                        category="VENDOR_AUTHENTICITY",
                        severity="INFO",
                        score_impact=-100,
                        rule_code="RULE_OFFICIAL_AUTHOR_DOMAIN",
                        human_description=f"Author email '{meta.author_email}' verified as authorized official vendor domain.",
                        metadata={"author_email": meta.author_email, "entity": candidate.entity_token},
                    )
                )
                accumulated_score = 0
            elif is_vendor_repo:
                accumulated_score = max(0, accumulated_score - 40)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_OFFICIAL_VENDOR_REPO_LINEAGE",
                        category="VENDOR_AUTHENTICITY",
                        severity="INFO",
                        score_impact=-40,
                        rule_code="RULE_OFFICIAL_REPO_LINEAGE",
                        human_description=f"Project homepage links to official vendor organization repository ({meta.homepage}).",
                        metadata={"homepage": meta.homepage},
                    )
                )
            elif is_domain_aligned:
                # Publisher owns custom corporate domain matching package identifier (e.g. support@truthlocks.com for truthlocks-crewai)
                accumulated_score = max(0, accumulated_score - 25)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_ORGANIZATIONAL_DOMAIN_NAME_ALIGNMENT",
                        category="VENDOR_AUTHENTICITY",
                        severity="INFO",
                        score_impact=-25,
                        rule_code="RULE_ORGANIZATIONAL_DOMAIN_ALIGNMENT",
                        human_description=f"Publisher email domain '@{author_domain}' matches package identifier token '{domain_root}', verifying identifiable third-party organization ownership.",
                        metadata={"author_email": meta.author_email, "matched_token": domain_root, "author_domain": author_domain},
                    )
                )
            elif is_known_brand:
                accumulated_score += 25
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_UNVERIFIED_AUTHOR_DOMAIN",
                        category="VENDOR_AUTHENTICITY",
                        severity="HIGH",
                        score_impact=25,
                        rule_code="RULE_UNVERIFIED_AUTHOR_DOMAIN",
                        human_description=f"Publisher email '{meta.author_email}' is not affiliated with official vendor domain.",
                        metadata={"author_email": meta.author_email, "entity": candidate.entity_token},
                    )
                )

            # Package Structural Effort Signals (+/- 15 pts)
            desc_len = len(meta.description or "")
            if desc_len > 200 and (meta.homepage or meta.project_urls):
                accumulated_score = max(0, accumulated_score - 15)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_HIGH_DOCUMENTATION_EFFORT",
                        category="PACKAGE_EFFORT",
                        severity="INFO",
                        score_impact=-15,
                        rule_code="RULE_RICH_DOCUMENTATION",
                        human_description=f"Legitimate documentation effort ({desc_len} chars with homepage link).",
                        metadata={"desc_len": desc_len},
                    )
                )
            elif desc_len < 30:
                accumulated_score += 15
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_EMPTY_OR_MINIMAL_DESCRIPTION",
                        category="PACKAGE_EFFORT",
                        severity="MEDIUM",
                        score_impact=15,
                        rule_code="RULE_MINIMAL_DESCRIPTION",
                        human_description="Package has empty or near-zero description (potential reservation stub).",
                        metadata={"desc_len": desc_len},
                    )
                )

            # URL Confusion & SourceRank Hijacking (+30 pts)
            url_hijack = self.check_url_confusion_hijacking(pkg_name, meta.homepage, meta.project_urls, is_vendor_domain)
            if url_hijack:
                claimed_repo, official_pkg = url_hijack
                accumulated_score += 30
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_URL_CONFUSION_HIJACKING",
                        category="VENDOR_AUTHENTICITY",
                        severity="HIGH",
                        score_impact=30,
                        rule_code="RULE_URL_CONFUSION_SOURCERANK_HIJACK",
                        human_description=f"Package claims legitimate high-profile upstream repository '{claimed_repo}' ({official_pkg}) in metadata to artificially inflate trust / SourceRank.",
                        metadata={"claimed_repo": claimed_repo, "official_package": official_pkg},
                    )
                )

            # Rapid SemVer Burst Velocity (+15 pts)
            if getattr(meta, "has_rapid_semver_burst", False) and not is_vendor_domain:
                accumulated_score += 15
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_RAPID_SEMVER_BURST",
                        category="PACKAGE_EFFORT",
                        severity="MEDIUM",
                        score_impact=15,
                        rule_code="RULE_RAPID_SEMVER_BURST",
                        human_description=f"Package published {meta.release_count} versions in rapid succession (< 24h) to mimic mature open source maintenance.",
                        metadata={"release_count": meta.release_count},
                    )
                )

            # ==================== 3. SLEEPER SQUATTING & DORMANCY RUBRIC (+10 to +20 pts) ====================
            first_pub_dt = meta.first_published_at or meta.published_at
            dormancy_pts, dormancy_sig, days_dormant = self.calculate_dormancy_signals(first_pub_dt)
            if dormancy_sig and not is_vendor_domain:
                accumulated_score += dormancy_pts
                evidence_signals.append(dormancy_sig)

            # ==================== 3b. VERSION CONFUSION & INFLATED MAJOR VERSION (+15 to +40 pts) ====================
            current_year = datetime.now(timezone.utc).year
            major_ver = self.extract_major_version(meta.latest_version)
            rel_count = getattr(meta, "release_count", 1) or 1
            is_inflated_version_risk = False
            is_valid_calver_year = False
            is_future_year_anomaly = False

            # Check if major version represents a Calendar Year (CalVer, e.g. 2024.3.13)
            if 1990 <= major_ver <= (current_year + 1):
                is_valid_calver_year = True
            elif (current_year + 1) < major_ver <= 3000:
                is_future_year_anomaly = True

            # Check for YYYYMM / YYYYMMDD date-stamp versioning (e.g. v202605.0 = 2026-05,
            # v20260210 = 2026-02-10) — these fall well outside the bare-year range above
            # but are equally legitimate, non-suspicious versioning schemes.
            is_date_stamp = is_date_stamp_version(major_ver, current_year)

            if is_valid_calver_year or is_date_stamp:
                # Valid past/current calendar year, or a recognized date-stamp scheme:
                # completely standard versioning (e.g. 2024.1.0, or 202605.0 for May 2026).
                pass
            elif is_future_year_anomaly and not is_vendor_domain:
                # Suspicious future calendar year (e.g. v2099 or v2040)
                is_inflated_version_risk = True
                ver_pts = 35
                ver_sev = "HIGH"
                accumulated_score += ver_pts
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_FUTURE_YEAR_VERSION_ANOMALY",
                        category="VERSIONING_ANOMALY",
                        severity=ver_sev,
                        score_impact=ver_pts,
                        rule_code="RULE_FUTURE_CALVER_DATE",
                        human_description=(
                            f"Package registered with suspicious future calendar year version (v{meta.latest_version}, year {major_ver} > {current_year}), "
                            f"potentially attempting to ensure permanent dependency resolution dominance."
                        ),
                        metadata={
                            "latest_version": meta.latest_version,
                            "major_version": major_ver,
                            "current_year": current_year,
                            "is_inflated_version_risk": True,
                        },
                    )
                )
            elif major_ver >= 5 and not is_vendor_domain and days_dormant <= 365:
                is_inflated_version_risk = True
                if major_ver >= 50:
                    ver_pts = 40
                    ver_sev = "CRITICAL"
                elif major_ver >= 10:
                    ver_pts = 25
                    ver_sev = "HIGH"
                else:
                    ver_pts = 15
                    ver_sev = "MEDIUM"

                accumulated_score += ver_pts
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION",
                        category="VERSIONING_ANOMALY",
                        severity=ver_sev,
                        score_impact=ver_pts,
                        rule_code="RULE_INFLATED_MAJOR_VERSION",
                        human_description=(
                            f"Package registered with suspiciously high major version (v{meta.latest_version}, major {major_ver}) "
                            f"despite recent registration ({days_dormant} days ago, {rel_count} release(s)), "
                            f"indicating potential dependency confusion attack to shadow internal organization builds."
                        ),
                        metadata={
                            "latest_version": meta.latest_version,
                            "major_version": major_ver,
                            "days_dormant": days_dormant,
                            "release_count": rel_count,
                            "is_inflated_version_risk": True,
                        },
                    )
                )

            # ==================== 3c. INTERNAL NAMESPACE CONFUSION KEYWORD (+15 pts) ====================
            import re
            name_tokens = [t.lower() for t in re.split(r"[-_.]+", pkg_name)]
            has_internal_keyword = "internal" in name_tokens or any(
                t.startswith("internal") or t.endswith("internal") for t in name_tokens if len(t) <= 15
            )

            if has_internal_keyword and not is_vendor_domain:
                accumulated_score += 15
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_INTERNAL_NAMESPACE_CONFUSION",
                        category="NAMING_HEURISTIC",
                        severity="MEDIUM",
                        score_impact=15,
                        rule_code="RULE_INTERNAL_KEYWORD_HEURISTIC",
                        human_description=(
                            f"Package name '{pkg_name}' contains 'internal' namespace token, "
                            f"a common indicator of targeted dependency confusion attacks or internal library shadowing."
                        ),
                        metadata={
                            "package_name": pkg_name,
                            "matched_keyword": "internal",
                            "name_tokens": name_tokens,
                        },
                    )
                )

            # ==================== 4. AST CODE ANALYSIS & WEAPONIZATION (+25 to +45 pts) ====================
            ast_report = await adapter.download_and_inspect_payload(pkg_name, meta.latest_version)
            has_malware_hooks = False

            if ast_report.flags:
                for f in ast_report.flags:
                    # Was previously narrowed to Python-only ("SOCKET"+"INSTALL_TIME" or
                    # "REVERSE_SHELL"), so an npm package with e.g. a "curl evil.com |
                    # bash" postinstall script could never trigger the CRITICAL/malware
                    # path — npm's manifest inspector emits LIFECYCLE_SCRIPT /
                    # SUSPICIOUS_SHELL_COMMAND, neither of which matched.
                    is_stealer = "CONFIRMED_STEALER" in f
                    is_crit = f.startswith(CONFIRMED_DANGEROUS_FLAG_PREFIXES) or "REVERSE_SHELL" in f
                    is_suspicious_hook = "INSTALL_TIME" in f or "LIFECYCLE" in f
                    pts = 85 if is_stealer else 45 if is_crit else 25 if is_suspicious_hook else 15
                    accumulated_score += pts
                    if is_crit:
                        has_malware_hooks = True

                    evidence_signals.append(
                        EvidenceSignal(
                            signal_id="SIGNAL_WEAPONIZED_MALICIOUS_PAYLOAD" if is_crit else "SIGNAL_SUSPICIOUS_AST_PATTERN",
                            category="CODE_ANALYSIS",
                            severity="CRITICAL" if is_crit else "HIGH",
                            score_impact=pts,
                            rule_code="RULE_AST_WEAPONIZED_EXEC" if is_crit else "RULE_AST_SUSPICIOUS_CALL",
                            human_description=f,
                            is_critical=is_crit,
                            metadata={"flag": f},
                        )
                    )

                if has_confirmed_dangerous_execution(ast_report.flags):
                    has_malware_hooks = True
            elif not is_vendor_domain:
                # Clean code signal
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_AST_CODE_SAFE",
                        category="CODE_ANALYSIS",
                        severity="INFO",
                        score_impact=0,
                        rule_code="RULE_AST_CLEAN",
                        human_description="No malicious install-time hooks or shell cradles detected in package AST.",
                        metadata={"verdict": "CLEAN"},
                    )
                )

            # Codebase Size & Effort Signals
            if ast_report.is_empty_stub and not is_vendor_domain:
                accumulated_score += 15
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_EMPTY_CODE_STUB",
                        category="PACKAGE_EFFORT",
                        severity="MEDIUM",
                        score_impact=15,
                        rule_code="RULE_EMPTY_CODE_STUB",
                        human_description=f"Package is an empty placeholder ({ast_report.total_lines_of_code} LOC, {ast_report.total_source_files} file(s), {ast_report.total_code_size_bytes} bytes).",
                        metadata={
                            "total_lines_of_code": ast_report.total_lines_of_code,
                            "total_source_files": ast_report.total_source_files,
                            "code_size_bytes": ast_report.total_code_size_bytes,
                            "code_size_tier": ast_report.code_size_tier,
                        },
                    )
                )
            elif ast_report.total_lines_of_code >= 500:
                accumulated_score = max(0, accumulated_score - 15)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_SUBSTANTIAL_CODEBASE",
                        category="PACKAGE_EFFORT",
                        severity="INFO",
                        score_impact=-15,
                        rule_code="RULE_SUBSTANTIAL_CODEBASE",
                        human_description=f"Substantial functional codebase ({ast_report.total_lines_of_code} LOC across {ast_report.total_source_files} file(s)).",
                        metadata={
                            "total_lines_of_code": ast_report.total_lines_of_code,
                            "total_source_files": ast_report.total_source_files,
                            "code_size_bytes": ast_report.total_code_size_bytes,
                            "code_size_tier": ast_report.code_size_tier,
                        },
                    )
                )

            # ==================== 4b. PLUGIN DETECTORS (sentinel.detectors) ====================
            # Auto-discovered detector modules run here with full metadata + payload
            # context. Their findings are folded into the same additive rubric and
            # gate MALICIOUS exactly like built-in signals when catalogued as such.
            plugin_findings = await self._run_plugin_detectors(
                candidate=candidate,
                pkg_name=pkg_name,
                meta=meta,
                ast_report=ast_report,
                existing_signals=evidence_signals,
            )
            existing_codes = {s.signal_id for s in evidence_signals}
            for pf in plugin_findings:
                if pf.code in existing_codes:
                    continue
                existing_codes.add(pf.code)
                evidence_signals.append(pf.to_evidence_signal())
                accumulated_score += int(pf.score or 0)
                if pf.gates_malicious:
                    has_malware_hooks = True

            # ==================== 5. USAGE & ADOPTION RUBRIC (-40 to +10 pts) ====================
            monthly_dl = meta.monthly_downloads or 0
            weekly_dl = meta.weekly_downloads or 0
            daily_dl = meta.daily_downloads or 0

            if monthly_dl >= 10000:
                adoption_tier = "HIGH_COMMUNITY_ADOPTION"
                accumulated_score = max(0, accumulated_score - 40)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_HIGH_COMMUNITY_ADOPTION",
                        category="COMMUNITY_ADOPTION",
                        severity="INFO",
                        score_impact=-40,
                        rule_code="RULE_POPULAR_COMMUNITY_PACKAGE",
                        human_description=f"High community adoption with {monthly_dl:,} monthly downloads, demonstrating established trust.",
                        metadata={"monthly_downloads": monthly_dl, "weekly_downloads": weekly_dl},
                    )
                )
            elif monthly_dl >= 1000:
                adoption_tier = "ACTIVE_COMMUNITY_USE"
                accumulated_score = max(0, accumulated_score - 20)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_ACTIVE_COMMUNITY_USAGE",
                        category="COMMUNITY_ADOPTION",
                        severity="INFO",
                        score_impact=-20,
                        rule_code="RULE_ACTIVE_COMMUNITY_USAGE",
                        human_description=f"Active community usage with {monthly_dl:,} monthly downloads.",
                        metadata={"monthly_downloads": monthly_dl, "weekly_downloads": weekly_dl},
                    )
                )
            elif monthly_dl >= 100:
                adoption_tier = "MODERATE_USAGE"
                accumulated_score = max(0, accumulated_score - 10)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_MODERATE_COMMUNITY_USAGE",
                        category="COMMUNITY_ADOPTION",
                        severity="INFO",
                        score_impact=-10,
                        rule_code="RULE_MODERATE_COMMUNITY_USAGE",
                        human_description=f"Moderate community usage with {monthly_dl:,} monthly downloads.",
                        metadata={"monthly_downloads": monthly_dl},
                    )
                )
            else:
                adoption_tier = "NEGLIGIBLE_OR_ZERO_USAGE"

            # ==================== 5b. UPSTREAM REGISTRY DEPRECATION ====================
            is_deprecated_pkg = bool(getattr(meta, "is_deprecated", False))
            if is_deprecated_pkg:
                dep_reason = getattr(meta, "deprecation_reason", None) or "Package marked deprecated or yanked by upstream registry"
                accumulated_score = max(0, accumulated_score - 30)
                evidence_signals.append(
                    EvidenceSignal(
                        signal_id="SIGNAL_REGISTRY_DEPRECATED",
                        category="MAINTENANCE",
                        severity="INFO",
                        score_impact=-30,
                        rule_code="RULE_REGISTRY_DEPRECATED",
                        human_description=f"Package officially deprecated/yanked by upstream registry: '{dep_reason}'.",
                        metadata={"is_deprecated": True, "deprecation_reason": dep_reason},
                    )
                )

            # ==================== 6. SIGNAL QUALITY & IMPACT METRICS ====================
            critical_count = sum(1 for s in evidence_signals if s.severity == "CRITICAL" and s.score_impact > 0)
            high_count = sum(1 for s in evidence_signals if s.severity == "HIGH" and s.score_impact > 0)
            medium_count = sum(1 for s in evidence_signals if s.severity == "MEDIUM" and s.score_impact > 0)
            active_signals_count = len([s for s in evidence_signals if s.score_impact > 0])
            signal_quality_score = (critical_count * 50) + (high_count * 25) + (medium_count * 10)

            # ==================== FINAL COMPOSITE SCORE & VERDICT ====================
            is_extensible_framework = (
                candidate.entity_token.lower() in {
                    "langchain", "langgraph", "langsmith", "llamaindex", "crewai",
                    "autogen", "fastapi", "django", "flask", "pydantic", "pytest",
                    "jupyter", "jupyterlab", "ollama", "claude", "copilot", "mcp",
                    "openai", "anthropic", "gemini", "mistral", "deepseek", "huggingface",
                    "replicate", "cohere", "groq", "bedrock", "aws", "azure", "gcp",
                    "chromadb", "weaviate", "qdrant", "pinecone", "superduper",
                    "airflow", "prefect", "dagster", "celery", "odoo", "cdk", "terraform",
                }
                or candidate.framework_token.lower() in {
                    "mcp", "copilot", "agent", "plugin", "extension", "connector",
                    "adapter", "provider", "client", "wrapper", "integration", "sdk",
                }
            )

            is_official_vendor = is_vendor_domain or (is_vendor_repo and (monthly_dl >= 1000 or ast_report.total_lines_of_code >= 200))

            if is_official_vendor:
                verdict = ThreatVerdict.VERIFIED_OFFICIAL
                final_score = 0
            elif is_deprecated_pkg and days_dormant > 730:
                # Pre-AI historical packages abandoned/deprecated years ago (e.g. gemini-web from 2017)
                # are legacy projects, not active modern slopsquatting attacks.
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(25, max(5, accumulated_score // 5))
            elif has_malware_hooks and not is_deprecated_pkg:
                # Confirmed dangerous install-time code execution on active package
                verdict = ThreatVerdict.MALICIOUS
                final_score = max(120, accumulated_score + 50)
            elif is_deprecated_pkg and not has_malware_hooks:
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(20, max(5, accumulated_score // 5))
            elif has_malware_hooks:
                # Deprecated package with suspicious execution hooks
                verdict = ThreatVerdict.SUSPICIOUS
                final_score = min(60, max(30, accumulated_score // 2))
            elif is_domain_aligned and not has_malware_hooks:
                # Identifiable organization publishing integration under custom matching domain (e.g. truthlocks.com for truthlocks-crewai)
                verdict = ThreatVerdict.BENIGN_COMMUNITY if (monthly_dl >= 100 or ast_report.total_lines_of_code >= 30) else ThreatVerdict.SQUATTED_STUB if ast_report.is_empty_stub else ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(35, max(5, accumulated_score // 5)) if verdict == ThreatVerdict.BENIGN_COMMUNITY else min(40, max(20, accumulated_score // 2))
            elif is_extensible_framework and not has_malware_hooks and ast_report.total_lines_of_code >= 35:
                # Genuine integration extension / plugin for open-source AI frameworks & protocols
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(35, max(5, accumulated_score // 5))
            elif monthly_dl >= 1000 or (
                ast_report.total_lines_of_code >= 150
                and not has_malware_hooks
                and not ast_report.is_empty_stub
                and not is_inflated_version_risk
                and not url_hijack
            ):
                # Genuine moderate-to-large community codebase with clean AST and no supply chain weaponization
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(35, max(5, accumulated_score // 5))
            elif not is_known_brand:
                # Generic non-brand developer project (e.g. nester, pyglw)
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(25, max(5, accumulated_score // 5))
            elif ast_report.is_empty_stub and is_known_brand:
                # 0 distribution files or empty unverified placeholder claiming high-value brand (sleeper squat risk)
                verdict = ThreatVerdict.SQUATTED_STUB
                final_score = min(75, max(45, accumulated_score))
            elif accumulated_score >= 60 and is_known_brand:
                # Unverified brand claim
                verdict = ThreatVerdict.SUSPICIOUS
                final_score = min(95, max(60, accumulated_score))
            else:
                verdict = ThreatVerdict.BENIGN_COMMUNITY
                final_score = min(35, max(5, accumulated_score // 5))

            first_pub = meta.first_published_at or meta.published_at
            latest_rel = meta.latest_release_at or meta.published_at
            now_utc = datetime.now(timezone.utc)

            return SquatDetection(
                candidate_id=candidate.candidate_id,
                ecosystem=ecosystem,
                package_name=pkg_name,
                author_username=meta.author,
                release_version=meta.latest_version,
                published_at=first_pub,
                first_published_at=first_pub,
                latest_release_at=latest_rel,
                discovered_at=now_utc,
                last_audited_at=now_utc,
                threat_score=final_score,
                is_deprecated=is_deprecated_pkg,
                deprecation_reason=getattr(meta, "deprecation_reason", None),
                analysis_details={
                    "is_deprecated": is_deprecated_pkg,
                    "deprecation_reason": getattr(meta, "deprecation_reason", None),
                    "entity": candidate.entity_token,
                    "capability": candidate.capability_token,
                    "framework": candidate.framework_token,
                    "author_email": meta.author_email,
                    "homepage": meta.homepage,
                    "flags": ast_report.flags,
                    "line_details": ast_report.line_details,
                    "ast_verdict": ast_report.verdict.value,
                    "days_dormant": days_dormant,
                    "first_published_at": first_pub.isoformat(),
                    "latest_release_at": latest_rel.isoformat(),
                    "discovered_at": now_utc.isoformat(),
                    "last_audited_at": now_utc.isoformat(),
                    "is_official_vendor": is_official_vendor,
                    "major_version": major_ver,
                    "is_inflated_version_risk": is_inflated_version_risk,
                    "has_internal_keyword": has_internal_keyword,
                    "version_metrics": {
                        "latest_version": meta.latest_version,
                        "major_version": major_ver,
                        "is_inflated_version_risk": is_inflated_version_risk,
                        "is_calver_year": is_valid_calver_year,
                        "is_date_stamp_version": is_date_stamp,
                        "version_anomaly_tier": (
                            "FUTURE_YEAR_ANOMALY" if is_future_year_anomaly
                            else "CRITICAL_INFLATION" if (is_inflated_version_risk and major_ver >= 50)
                            else "HIGH_INFLATION" if (is_inflated_version_risk and major_ver >= 10)
                            else "MODERATE_INFLATION" if is_inflated_version_risk
                            else "STANDARD_DATE_STAMP" if is_date_stamp
                            else "STANDARD_CALVER" if is_valid_calver_year
                            else "STANDARD_VERSION"
                        ),
                    },
                    "code_metrics": {
                        "total_source_files": ast_report.total_source_files,
                        "total_lines_of_code": ast_report.total_lines_of_code,
                        "total_code_size_bytes": ast_report.total_code_size_bytes,
                        "is_empty_stub": ast_report.is_empty_stub,
                        "code_size_tier": ast_report.code_size_tier,
                    },
                    # Structured, indexed-in-SQL "can this run code at install/deploy time"
                    # fields (see SquatDetectionModel.has_install_hook /has_network_socket).
                    # Key names match the internal downstream sync table's pre-existing (previously
                    # dormant/unpopulated) generated columns of the same name.
                    "has_install_hook": has_install_time_code_execution(ast_report.flags),
                    "has_network_socket": has_install_time_network_socket(ast_report.flags),
                    "has_confirmed_dangerous_execution": has_malware_hooks,
                    "has_pth_execution": getattr(ast_report, "has_pth_execution", False),
                    "has_exfiltration_destination": getattr(ast_report, "has_exfiltration_destination", False),
                    "has_credential_harvesting": getattr(ast_report, "has_credential_harvesting", False),
                    "has_bundled_binary": getattr(ast_report, "has_bundled_binary", False),
                    "usage_metrics": {
                        "monthly_downloads": monthly_dl,
                        "weekly_downloads": weekly_dl,
                        "daily_downloads": daily_dl,
                        "adoption_tier": adoption_tier,
                    },
                    "signals": [s.model_dump() for s in evidence_signals],
                    # Unified typed signal layer — persisted to sentinel_findings
                    # for query-anywhere UI filtering (see sentinel.core.signals).
                    "findings": [
                        f.model_dump(mode="json")
                        for f in build_findings(evidence_signals, ast_report.flags)
                    ],
                    "point_rubric_breakdown": {
                        "raw_accumulated_points": accumulated_score,
                        "signal_quality_score": signal_quality_score,
                        "active_signals_count": active_signals_count,
                        "critical_signals_count": critical_count,
                        "high_signals_count": high_count,
                        "medium_signals_count": medium_count,
                        "final_threat_score": final_score,
                    }
                },
                verdict=verdict,
            )


    async def evaluate_batch_with_budget(
        self,
        candidates: List[WatchlistCandidate],
    ) -> List[SquatDetection]:
        """Evaluate a batch of candidates within strict timeout budget."""
        results: List[SquatDetection] = []
        try:
            tasks = [self.evaluate_candidate(c) for c in candidates]
            done = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.global_timeout_seconds,
            )
            for res in done:
                if isinstance(res, SquatDetection):
                    results.append(res)
        except asyncio.TimeoutError:
            pass
        return results
