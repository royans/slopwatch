"""
Sentinel Curated Taxonomies.

Defines the multi-ecosystem vocabulary for generating long-tail composable
package candidate spaces across Entities, Capabilities, and Frameworks.
"""

from typing import List, Dict

# 500+ Enterprise Tech Entities / Cloud / DB / AI Vendors
ENTITIES: List[str] = [
    # Cloud Providers & Infra
    "google", "google-cloud", "gcp", "microsoft", "azure", "aws", "amazon",
    "cloudflare", "digitalocean", "hetzner", "linode", "oracle-cloud", "alibaba-cloud",
    "kubernetes", "k8s", "docker", "terraform", "ansible", "pulumi", "helm",
    "nomad", "consul", "vault", "envoy", "istio", "traefik", "nginx", "caddy", "kong",

    # Databases & Storage
    "snowflake", "supabase", "clickhouse", "postgres", "postgresql",
    "sqlite", "mongodb", "mongo", "redis", "valkey", "memcached",
    "cassandra", "scylladb", "couchbase", "dynamodb", "cosmosdb", "neo4j",
    "arangodb", "faunadb", "cockroachdb", "cockroach", "yugabyte", "duckdb",
    "polars", "dbt", "databricks", "delta-lake", "iceberg", "hudi", "trino",
    "presto", "elasticsearch", "elastic", "opensearch", "meilisearch", "typesense",
    "minio", "ceph", "s3", "blob", "gcs",

    # AI, ML & Vector Stores
    "openai", "anthropic", "claude", "gemini", "deepmind", "mistral", "mistralai",
    "deepseek", "deepseek-ai", "cohere", "meta-llama", "llama", "pytorch",
    "huggingface", "hf", "transformers", "langchain", "langgraph", "langsmith",
    "llamaindex", "haystack", "autogen", "crewai", "vllm", "ollama", "groq",
    "together", "together-ai", "replicate", "fireworks", "fireworks-ai", "modal",
    "baseten", "fal", "fal-ai", "perplexity", "perplexity-ai", "xai", "grok",
    "elevenlabs", "runway", "runwayml", "stability", "stability-ai", "midjourney",
    "cursor", "copilot", "dspy", "instructor", "semantic-kernel", "unstructured",
    "voyage", "voyageai", "weaviate", "pinecone", "qdrant", "chroma", "chromadb",
    "milvus", "zilliz", "vespa", "faiss", "pgvector", "sagemaker", "bedrock",
    "vertex-ai", "azure-openai",

    # Crypto, Web3, Exchanges & Wallets
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

    # Auth, Identity & Security
    "okta", "auth0", "clerk", "stytch", "firebase-auth", "cognito", "keycloak",
    "ory", "kratos", "hydra", "zitadel", "fusionauth", "onelogin", "pingidentity",
    "duo", "yubikey", "sentry", "datadog", "newrelic", "dynatrace", "splunk",
    "grafana", "prometheus", "jaeger", "opentelemetry", "otel", "crowdstrike",
    "snyk", "trivy", "wiz", "paloalto", "zscaler",

    # Payments, SaaS & Communications
    "stripe", "paypal", "square", "plaid", "adyen", "braintree", "paddle",
    "shopify", "twilio", "sendgrid", "resend", "postmark", "mailgun", "loops",
    "slack", "discord", "telegram", "whatsapp", "zoom", "notion", "airtable",
    "linear", "jira", "github", "gitlab", "bitbucket", "pagerduty", "opsgenie",
    "workspace",

    # Message Brokers & Streaming
    "kafka", "rabbitmq", "celery", "nats", "redis-queue", "rq", "bullmq",
    "pulsar", "zeromq", "sqs", "sns", "pubsub", "kinesis", "eventbridge"
]

# 60+ Functional Capabilities & Protocols
CAPABILITIES: List[str] = [
    # Auth & Identity
    "auth", "sso", "jwt", "oauth2", "oauth", "oidc", "saml", "pkce", "session",
    "tokens", "login", "mfa", "rbac", "permissions", "iam",

    # Client & Integration
    "client", "sdk", "connector", "driver", "api", "wrapper", "binding",
    "middleware", "interceptor", "adapter", "plugin", "extension", "bridge",

    # Data & Async
    "async", "aio", "sync", "queue", "worker", "tasks", "streaming", "events",
    "consumer", "producer", "pipeline", "batch", "loader", "exporter", "importer",

    # AI & Search
    "vectorstore", "embeddings", "rag", "retriever", "memory", "agents",
    "tools", "evaluator", "guardrails",

    # Telemetry & Ops
    "telemetry", "tracing", "metrics", "logging", "logger", "monitor",
    "profiler", "healthcheck", "exporter", "collector",

    # Utilities & Models
    "models", "schemas", "types", "helpers", "utils", "core", "common",
    "validator", "serializer", "cache", "storage", "pool"
]

# Ecosystem-Specific Frameworks
FRAMEWORKS: Dict[str, List[str]] = {
    "pypi": [
        "fastapi", "flask", "django", "pydantic", "langchain", "llamaindex",
        "celery", "sqlalchemy", "tortoise", "ormar", "peewee", "asyncpg",
        "motor", "aiohttp", "httpx", "requests", "sanic", "tornado",
        "strawberry", "graphene", "pytest", "click", "typer"
    ],
    "npm": [
        "react", "next", "nextjs", "vue", "nuxt", "svelte", "sveltekit",
        "angular", "express", "nest", "nestjs", "fastify", "koa", "hono",
        "trpc", "prisma", "drizzle", "typeorm", "mongoose", "axios",
        "tailwind", "vite", "webpack", "rollup"
    ]
}

# Delimiters per ecosystem
DELIMITERS: Dict[str, List[str]] = {
    "pypi": ["-", "_"],
    "npm": ["-", "/"]  # e.g., @auth/azure-jwt or auth-azure-jwt
}

# Verified Official Vendor Domain Suffixes (for zero false-positive whitelisting)
VENDOR_DOMAINS: Dict[str, List[str]] = {
    "google": ["google.com", "google.org"],
    "google-cloud": ["google.com", "google.org"],
    "gcp": ["google.com", "google.org"],
    "microsoft": ["microsoft.com"],
    "azure": ["microsoft.com"],
    "aws": ["amazon.com", "aws.amazon.com"],
    "amazon": ["amazon.com"],
    "cloudflare": ["cloudflare.com"],
    "snowflake": ["snowflake.com"],
    "supabase": ["supabase.com", "supabase.io"],
    "stripe": ["stripe.com"],
    "okta": ["okta.com", "auth0.com"],
    "auth0": ["auth0.com", "okta.com"],
    "clerk": ["clerk.com", "clerk.dev"],
    "workspace": ["google.com", "workspace.google.com"],
    # AI Companies & Ecosystems
    "openai": ["openai.com"],
    "anthropic": ["anthropic.com"],
    "claude": ["anthropic.com"],
    "deepmind": ["google.com"],
    "gemini": ["google.com"],
    "mistral": ["mistral.ai"],
    "mistralai": ["mistral.ai"],
    "deepseek": ["deepseek.com"],
    "cohere": ["cohere.com", "cohere.ai"],
    "meta-llama": ["meta.com", "facebook.com"],
    "llama": ["meta.com", "facebook.com"],
    "pytorch": ["pytorch.org", "meta.com"],
    "huggingface": ["huggingface.co"],
    "hf": ["huggingface.co"],
    "langchain": ["langchain.dev", "langchain.com"],
    "langgraph": ["langchain.dev", "langchain.com"],
    "langsmith": ["langchain.dev", "langchain.com"],
    "llamaindex": ["llamaindex.ai", "runllama.ai"],
    "crewai": ["crewai.com"],
    "groq": ["groq.com"],
    "together": ["together.ai", "together.xyz"],
    "together-ai": ["together.ai", "together.xyz"],
    "replicate": ["replicate.com"],
    "fireworks": ["fireworks.ai"],
    "fireworks-ai": ["fireworks.ai"],
    "modal": ["modal.com"],
    "baseten": ["baseten.co"],
    "fal": ["fal.ai"],
    "fal-ai": ["fal.ai"],
    "perplexity": ["perplexity.ai"],
    "perplexity-ai": ["perplexity.ai"],
    "xai": ["x.ai"],
    "grok": ["x.ai"],
    "elevenlabs": ["elevenlabs.io"],
    "runway": ["runwayml.com"],
    "runwayml": ["runwayml.com"],
    "stability": ["stability.ai"],
    "stability-ai": ["stability.ai"],
    "midjourney": ["midjourney.com"],
    "cursor": ["cursor.com", "cursor.sh", "anysphere.co"],
    "copilot": ["github.com", "microsoft.com"],
    "pinecone": ["pinecone.io"],
    "weaviate": ["weaviate.io", "semi.technology"],
    "qdrant": ["qdrant.com", "qdrant.to"],
    "chroma": ["trychroma.com"],
    "chromadb": ["trychroma.com"],
    "milvus": ["zilliz.com", "milvus.io"],
    "zilliz": ["zilliz.com", "milvus.io"],
    "vespa": ["vespa.ai"],
    "voyage": ["voyageai.com"],
    "voyageai": ["voyageai.com"],
    "datadog": ["datadoghq.com"],
    "sentry": ["sentry.io"],
    "twilio": ["twilio.com"],
    "github": ["github.com"],
    # Crypto Companies, Exchanges, Wallets, Chains & DeFi
    "bitcoin": ["bitcoin.org", "bitcoincore.org"],
    "btc": ["bitcoin.org", "bitcoincore.org"],
    "ethereum": ["ethereum.org", "ethereum.foundation"],
    "eth": ["ethereum.org", "ethereum.foundation"],
    "solana": ["solana.com", "solanalabs.com"],
    "sol": ["solana.com", "solanalabs.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "kraken": ["kraken.com"],
    "okx": ["okx.com"],
    "bybit": ["bybit.com"],
    "kucoin": ["kucoin.com"],
    "bitfinex": ["bitfinex.com"],
    "crypto-com": ["crypto.com"],
    "cryptocom": ["crypto.com"],
    "gateio": ["gate.io"],
    "deribit": ["deribit.com"],
    "bitget": ["bitget.com"],
    "mexc": ["mexc.com"],
    "bitstamp": ["bitstamp.net"],
    "metamask": ["consensys.io", "metamask.io"],
    "ledger": ["ledger.com"],
    "trezor": ["trezor.io", "satoshilabs.com"],
    "phantom": ["phantom.app"],
    "trustwallet": ["trustwallet.com"],
    "exodus": ["exodus.com"],
    "safe": ["safe.global"],
    "gnosis-safe": ["safe.global", "gnosis.io"],
    "walletconnect": ["walletconnect.com", "walletconnect.org"],
    "uniswap": ["uniswap.org"],
    "aave": ["aave.com"],
    "compound": ["compound.finance"],
    "curve": ["curve.fi"],
    "makerdao": ["makerdao.com"],
    "lido": ["lido.fi"],
    "pancakeswap": ["pancakeswap.finance"],
    "sushiswap": ["sushi.com"],
    "dydx": ["dydx.exchange"],
    "1inch": ["1inch.io"],
    "jupiter": ["jup.ag"],
    "hyperliquid": ["hyperliquid.xyz"],
    "chainlink": ["chain.link", "smartcontract.com"],
    "alchemy": ["alchemy.com"],
    "infura": ["infura.io", "consensys.io"],
    "quicknode": ["quicknode.com"],
    "moralis": ["moralis.io"],
    "thegraph": ["thegraph.com", "edgeandnode.com"],
    "polygon": ["polygon.technology"],
    "matic": ["polygon.technology"],
    "arbitrum": ["arbitrum.io", "offchainlabs.com"],
    "optimism": ["optimism.io", "oplabs.co"],
    "base": ["base.org", "coinbase.com"],
    "ripple": ["ripple.com"],
    "xrp": ["ripple.com"],
    "tron": ["tron.network"],
    "near": ["near.org", "near.foundation"],
    "aptos": ["aptoslabs.com", "aptosfoundation.org"],
    "sui": ["mystenlabs.com", "sui.io"],
    "ton": ["ton.org"],
    "monero": ["getmonero.org"],
    "circle": ["circle.com"],
    "tether": ["tether.to"],
    "paxos": ["paxos.com"],
    "opensea": ["opensea.io"],
    "blur": ["blur.io"],
    "magic-eden": ["magiceden.io"],
}

# Generic Free / Public Email Providers (Shared by millions of independent developers)
PUBLIC_EMAIL_PROVIDERS: List[str] = [
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "rocketmail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me",
    "tutanota.com", "tuta.io",
    "mail.com", "gmx.com", "gmx.net",
    "zoho.com", "zohomail.com",
    "yandex.com", "yandex.ru", "ya.ru",
    "qq.com", "163.com", "126.com", "sina.com", "foxmail.com",
    "aol.com", "aim.com",
    "fastmail.com", "fastmail.fm",
]

# Disposable / Temporary Email Services (High risk of throwaway attacker accounts)
DISPOSABLE_EMAIL_DOMAINS: List[str] = [
    "tempmail.org", "10minutemail.com", "guerrillamail.com", "mailinator.com",
    "trashmail.com", "getairmail.com", "dispostable.com", "yopmail.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "temp-mail.org",
    "fakemailgenerator.com", "throwawaymail.com", "burnermail.io",
]


