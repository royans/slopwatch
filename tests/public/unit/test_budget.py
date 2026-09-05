import pytest
from slopwatch.core.budget import TokenBucketLimiter
from slopwatch.core.exceptions import BudgetExceededError


@pytest.mark.asyncio
async def test_token_bucket_normal_consumption():
    limiter = TokenBucketLimiter(max_hourly_tokens=1000, pause_threshold_pct=0.90)
    
    can_consume = await limiter.can_consume(500)
    assert can_consume is True
    
    consumed = await limiter.record_consumption(prompt_tokens=200, completion_tokens=300)
    assert consumed == 500
    
    stats = await limiter.get_usage_stats()
    assert stats["consumed_tokens"] == 500
    assert stats["remaining_tokens"] == 400


@pytest.mark.asyncio
async def test_token_bucket_threshold_exceeded():
    limiter = TokenBucketLimiter(max_hourly_tokens=1000, pause_threshold_pct=0.90)
    # Threshold is 900
    await limiter.record_consumption(prompt_tokens=400, completion_tokens=400) # 800 total
    
    # 800 + 200 = 1000 > 900 -> should return False for can_consume(200)
    can_consume = await limiter.can_consume(200)
    assert can_consume is False

    # Attempting to record consumption that reaches 900 raises BudgetExceededError
    with pytest.raises(BudgetExceededError) as exc_info:
        await limiter.record_consumption(prompt_tokens=50, completion_tokens=60) # 910 total
    
    assert "safety threshold" in str(exc_info.value)
