"""
Sentinel Configuration Manager.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    name: str = "slopwatch"
    version: str = "0.1.0"
    env: str = "development"
    log_level: str = "INFO"


class StorageConfig(BaseModel):
    database_url: str = "sqlite+aiosqlite:///data/slopwatch.db"
    wal_mode: bool = True


class ElicitorConfig(BaseModel):
    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    temperature: float = 0.7
    iterations_n: int = 10
    recurrence_threshold: float = 0.60
    max_hourly_tokens: int = 50000
    budget_pause_threshold_pct: float = 0.90


class SlopWatchConfig(BaseModel):
    crt_sh_url: str = "https://crt.sh/"
    concurrency_limit: int = 2
    request_timeout_seconds: int = 30
    retry_backoff_base_seconds: int = 2
    retry_max_seconds: int = 30
    max_retries: int = 3


# Backwards compatibility alias
SentinelConfig = SlopWatchConfig


def _find_default_signatures_path() -> str:
    """Locate parking_hashes.json via package resources, repo tree, or relative path."""
    try:
        import importlib.resources as pkg_resources
        sig_pkg = pkg_resources.files("slopwatch") / "signatures" / "parking_hashes.json"
        if sig_pkg.is_file():
            return str(sig_pkg)
    except Exception:
        pass
    in_tree = Path(__file__).resolve().parent.parent / "signatures" / "parking_hashes.json"
    if in_tree.exists():
        return str(in_tree)
    repo_cfg = Path(__file__).resolve().parent.parent.parent.parent / "config" / "signatures" / "parking_hashes.json"
    if repo_cfg.exists():
        return str(repo_cfg)
    return "config/signatures/parking_hashes.json"


class AssessorConfig(BaseModel):
    dns_timeout_seconds: float = 5.0
    http_timeout_seconds: float = 10.0
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    )
    signatures_path: str = Field(default_factory=_find_default_signatures_path)
    alert_score_threshold: int = 70


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    elicitor: ElicitorConfig = Field(default_factory=ElicitorConfig)
    slopwatch: SlopWatchConfig = Field(default_factory=SlopWatchConfig)
    assessor: AssessorConfig = Field(default_factory=AssessorConfig)

    @property
    def sentinel(self) -> SlopWatchConfig:
        return self.slopwatch

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Settings":
        """Load settings from YAML file with environment variable overrides."""
        config_dict: Dict[str, Any] = {}

        path_to_try = config_path or os.getenv("SLOPWATCH_CONFIG_PATH") or os.getenv("SENTINEL_CONFIG_PATH")
        if not path_to_try:
            default_paths = [
                Path("config/config.yaml"),
                Path("config/config.yaml.template"),
            ]
            for p in default_paths:
                if p.exists():
                    path_to_try = str(p)
                    break

        if path_to_try and Path(path_to_try).exists():
            with open(path_to_try, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config_dict = loaded

        # Support legacy sentinel key as alias for slopwatch:
        if "sentinel" in config_dict and "slopwatch" not in config_dict:
            config_dict["slopwatch"] = config_dict["sentinel"]

        # Allow environment variable overrides (SLOPWATCH_* preferred, fallback to SENTINEL_*)
        db_url = os.getenv("SLOPWATCH_DATABASE_URL") or os.getenv("SENTINEL_DATABASE_URL")
        if db_url:
            config_dict.setdefault("storage", {})["database_url"] = db_url

        llm_provider = os.getenv("SLOPWATCH_LLM_PROVIDER") or os.getenv("SENTINEL_LLM_PROVIDER")
        if llm_provider:
            config_dict.setdefault("elicitor", {})["provider"] = llm_provider

        return cls(**config_dict)
