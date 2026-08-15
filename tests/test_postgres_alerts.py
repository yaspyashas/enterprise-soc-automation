from dashboard.db_api import get_all_alerts


def test_get_all_alerts_returns_list():
    alerts = get_all_alerts()

    assert isinstance(alerts, list)


def test_get_all_alerts_structure():
    alerts = get_all_alerts()

    if not alerts:
        return

    required_fields = {
        "alert_id",
        "severity",
        "title",
        "status",
        "source_ip",
        "threat_type"
    }

    for alert in alerts:
        assert isinstance(alert, dict)
        assert required_fields.issubset(alert.keys())


def test_postgresql_alerts_have_valid_identifiers():
    alerts = get_all_alerts()

    for alert in alerts:
        assert isinstance(alert["alert_id"], str)
        assert alert["alert_id"] != ""

        assert isinstance(alert["severity"], str)
        assert alert["severity"] != ""

        assert isinstance(alert["status"], str)
        assert alert["status"] != ""