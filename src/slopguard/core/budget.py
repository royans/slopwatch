"""
Sentinel Token Budget Limiter.

Enforces strict hourly quotas on LLM token consumption and gracefully yields
when approaching the safety threshold (default 90% of cycle allocation).
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from slopguard.core.exceptions import BudgetExceededError


class TokenBucketLimiter:
    def __init__(
        self,
        max_hourly_tokens: int = 50000,
        pause_threshold_pct: float = 0.90,
    ):
        self.max_hourly_tokens = max_hourly_tokens
        self.pause_threshold = int(max_hourly_tokens * pause_threshold_pct)
        self.consumed_tokens = 0
        self.cycle_start: datetime = datetime.now(timezone.utc)
        self._lock = asyncio.Lock()

    def _reset_cycle_if_needed(self) -> None:
        """Reset consumed count if an hour has elapsed since cycle start."""
        now = datetime.now(timezone.utc)
        if now - self.cycle_start >= timedelta(hours=1):
            self.consumed_tokens = 0
            self.cycle_start = now

    async def can_consume(self, estimated_tokens: int = 500) -> bool:
        """Check if estimated tokens can be consumed without violating threshold."""
        async with self._lock:
            self._reset_cycle_if_needed()
            return (self.consumed_tokens + estimated_tokens) <= self.pause_threshold

    async def record_consumption(self, prompt_tokens: int, completion_tokens: int) -> int:
        """
        Record actual token usage from an LLM call.
        Raises BudgetExceededError if threshold is exceeded.
        """
        async with self._lock:
            self._reset_cycle_if_needed()
            total = prompt_tokens + completion_tokens
            self.consumed_tokens += total

            if self.consumed_tokens >= self.pause_threshold:
                raise BudgetExceededError(
                    f"LLM token consumption ({self.consumed_tokens} tokens) has reached or exceeded "
                    f"safety threshold ({self.pause_threshold}/{self.max_hourly_tokens}). "
                    f"Yielding until next cycle."
                )
            return self.consumed_tokens

    async def get_usage_stats(self) -> dict:
        """Return current cycle token usage stats."""
        async with self._lock:
            self._reset_cycle_if_needed()
            return {
                "consumed_tokens": self.consumed_tokens,
                "pause_threshold": self.pause_threshold,
                "max_hourly_tokens": self.max_hourly_tokens,
                "cycle_start": self.cycle_start.isoformat(),
                "remaining_tokens": max(0, self.pause_threshold - self.consumed_tokens),
            }
