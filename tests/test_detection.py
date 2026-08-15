from collector.linux_collector import LinuxLogCollector
from parser.log_parser import LogParser
from detection.detection_engine import DetectionEngine


def test_detection_returns_alerts():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()
    detector = DetectionEngine()

    logs = collector.collect()

    all_alerts = []

    for log in logs:
        event = parser.parse_log(log)
        alerts = detector.detect(event)
        all_alerts.extend(alerts)

    assert isinstance(all_alerts, list)
    assert len(all_alerts) > 0


def test_detection_alerts_are_dictionaries():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()
    detector = DetectionEngine()

    logs = collector.collect()

    all_alerts = []

    for log in logs:
        event = parser.parse_log(log)
        alerts = detector.detect(event)
        all_alerts.extend(alerts)

    assert all(
        isinstance(alert, dict)
        for alert in all_alerts
    )


def test_detection_alerts_have_required_fields():

    collector = LinuxLogCollector(
        "collector/sample_auth.log"
    )

    parser = LogParser()
    detector = DetectionEngine()

    logs = collector.collect()

    all_alerts = []

    for log in logs:
        event = parser.parse_log(log)
        alerts = detector.detect(event)
        all_alerts.extend(alerts)

    assert len(all_alerts) > 0

    required_fields = {
        "severity",
        "title",
        "description",
        "source_ip",
        "threat_type"
    }

    for alert in all_alerts:
        assert required_fields.issubset(
            alert.keys()
        )