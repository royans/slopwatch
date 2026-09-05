"""
SlopWatch Priority Brand Entity Weights and Matcher.
"""

from typing import Optional, Dict
from slopwatch.core.taxonomies import ENTITIES

# High-priority enterprise, Crypto & AI brands
PRIORITY_BRAND_WEIGHTS: Dict[str, int] = {
    # 🚨 Top Tier 1: Crypto Companies, Exchanges, Wallets, Chains & DeFi (Top Priority: 990-999)
    "bitcoin": 999,
    "btc": 999,
    "ethereum": 999,
    "eth": 999,
    "solana": 998,
    "sol": 998,
    "metamask": 998,
    "coinbase": 998,
    "binance": 998,
    "ledger": 997,
    "trezor": 997,
    "kraken": 997,
    "phantom": 997,
    "trustwallet": 996,
    "okx": 996,
    "bybit": 996,
    "crypto-com": 996,
    "cryptocom": 996,
    "uniswap": 995,
    "aave": 995,
    "web3": 995,
    "ethers": 995,
    "chainlink": 994,
    "alchemy": 994,
    "infura": 994,
    "polygon": 993,
    "matic": 993,
    "arbitrum": 993,
    "optimism": 993,
    "base": 993,
    "ripple": 992,
    "xrp": 992,
    "tron": 992,
    "tether": 991,
    "circle": 991,
    "safe": 991,
    "walletconnect": 991,
    "dydx": 990,
    "1inch": 990,
    "jupiter": 990,
    "opensea": 990,

    # Tier 2: Top AI Companies & Labs (High Priority: 920-960)
    "openai": 960,
    "anthropic": 960,
    "claude": 960,
    "deepseek": 960,
    "deepseek-ai": 960,
    "mistral": 950,
    "mistralai": 950,
    "cohere": 950,
    "gemini": 950,
    "deepmind": 950,
    "meta-llama": 950,
    "llama": 950,
    "groq": 950,
    "huggingface": 940,
    "hf": 940,
    "langchain": 940,
    "langgraph": 940,
    "llamaindex": 940,
    "crewai": 940,
    "vllm": 930,
    "ollama": 930,
    "perplexity": 930,
    "xai": 930,
    "grok": 930,
    "together": 920,
    "together-ai": 920,
    "replicate": 920,
    "elevenlabs": 920,
    "midjourney": 920,
    "stability": 920,
    "cursor": 920,
    "copilot": 920,
    "pinecone": 910,
    "weaviate": 910,
    "qdrant": 910,
    "chroma": 910,
    "chromadb": 910,

    # Tier 3: Major Cloud & Identity Platforms (800-880)
    "google": 880,
    "gcp": 880,
    "google-cloud": 880,
    "workspace": 880,
    "azure": 880,
    "microsoft": 880,
    "aws": 850,
    "amazon": 850,
    "okta": 850,
    "auth0": 850,
    "clerk": 820,
    "stripe": 820,
    "supabase": 820,
    "discord": 800,
    "shopify": 800,
}


def compute_brand_priority(package_name: str) -> Optional[tuple[str, int]]:
    """
    Check if a package name matches a priority brand entity and calculate boosted weight.
    """
    pkg_lower = package_name.lower().replace("_", "-")
    for brand, weight in PRIORITY_BRAND_WEIGHTS.items():
        if pkg_lower == brand or pkg_lower.startswith(f"{brand}-") or f"-{brand}-" in pkg_lower or pkg_lower.endswith(f"-{brand}"):
            return brand, weight
    for entity in ENTITIES:
        if pkg_lower == entity or pkg_lower.startswith(f"{entity}-") or f"-{entity}-" in pkg_lower or pkg_lower.endswith(f"-{entity}"):
            return entity, 750
    return None
