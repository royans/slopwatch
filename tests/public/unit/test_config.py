from sentinel.core.config import Settings


def test_default_config_loading():
    settings = Settings.load()
    assert settings.app.name == "flagthis_sentinel"
    assert settings.storage.wal_mode is True
    assert settings.elicitor.iterations_n == 10
    assert settings.elicitor.recurrence_threshold == 0.60
    assert settings.sentinel.concurrency_limit == 2
