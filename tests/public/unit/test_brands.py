from slopwatch.core.brands import compute_brand_priority, PRIORITY_BRAND_WEIGHTS


def test_compute_brand_priority():
    # 🚨 Top Tier 1: Crypto Priority brands
    res_crypto1 = compute_brand_priority("bitcoin-wallet-bridge")
    assert res_crypto1 is not None
    brand_c1, weight_c1 = res_crypto1
    assert brand_c1 == "bitcoin"
    assert weight_c1 >= 990

    res_crypto2 = compute_brand_priority("metamask-auth-connector")
    assert res_crypto2 is not None
    brand_c2, weight_c2 = res_crypto2
    assert brand_c2 == "metamask"
    assert weight_c2 >= 990

    # Tier 2: AI Priority brands
    res_ai = compute_brand_priority("openai-gpt-tools")
    assert res_ai is not None
    brand_ai, weight_ai = res_ai
    assert brand_ai == "openai"
    assert weight_ai == 960

    # Fallback to general entity if not in PRIORITY_BRAND_WEIGHTS
    res_entity = compute_brand_priority("docker-helper")
    assert res_entity is not None
    brand_e, weight_e = res_entity
    assert brand_e == "docker"
    assert weight_e == 750

    # Non-brand package
    assert compute_brand_priority("my-simple-utility-package-xyz") is None
