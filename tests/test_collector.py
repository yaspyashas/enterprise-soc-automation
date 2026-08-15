from collector.linux_collector import LinuxLogCollector


def test_linux_collector_returns_logs():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    logs = collector.collect()

    assert logs is not None
    assert isinstance(logs, list)


def test_linux_collector_collects_logs():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    logs = collector.collect()

    assert len(logs) > 0


def test_linux_collector_log_entries_are_strings():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    logs = collector.collect()

    assert all(
        isinstance(log, str)
        for log in logs
    )