from slopguard.core.config import Settings


def test_default_config_loading():
    settings = Settings.load()
    assert settings.app.name == "slopguard"
    assert settings.storage.wal_mode is True
    assert settings.elicitor.iterations_n == 10
    assert settings.elicitor.recurrence_threshold == 0.60
    assert settings.sentinel.concurrency_limit == 2

def test_slopguard_alias():
    settings = Settings.load()
    assert settings.slopguard.concurrency_limit == 2
