from collector.linux_collector import LinuxLogCollector
from parser.log_parser import LogParser


def test_parser_returns_event():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()

    logs = collector.collect()

    assert len(logs) > 0

    event = parser.parse_log(logs[0])

    assert event is not None
    assert isinstance(event, dict)


def test_parser_contains_expected_fields():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()

    logs = collector.collect()

    event = parser.parse_log(logs[0])

    assert "timestamp" in event
    assert "hostname" in event
    assert "service" in event
    assert "message" in event


def test_parser_parses_all_collected_logs():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()

    logs = collector.collect()

    parsed_events = [
        parser.parse_log(log)
        for log in logs
    ]

    assert len(parsed_events) == len(logs)

    assert all(
        isinstance(event, dict)
        for event in parsed_events
    )