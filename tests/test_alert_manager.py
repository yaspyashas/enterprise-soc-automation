import pytest

from alert_manager.alert_manager import create_alert
from database.db_connection import get_connection


def test_create_alert():
    detection = {
        "severity": "High",
        "title": "PYTEST SSH Brute Force Alert",
        "description": "Pytest alert creation test",
        "source_ip": "192.168.1.21",
        "threat_type": "SSH Brute Force",
        "timestamp": "Aug 15 pytest"
    }

    alert = create_alert(detection)

    assert alert is not None
    assert alert["alert_id"].startswith("ALT-")
    assert alert["severity"] == "High"
    assert alert["title"] == "PYTEST SSH Brute Force Alert"
    assert alert["source_ip"] == "192.168.1.21"
    assert alert["threat_type"] == "SSH Brute Force"
    assert alert["status"] == "Open"


def test_create_alert_saved_in_postgresql():
    detection = {
        "severity": "Medium",
        "title": "PYTEST PostgreSQL Alert",
        "description": "Verify alert is persisted in PostgreSQL",
        "source_ip": "192.168.1.22",
        "threat_type": "SSH Brute Force",
        "timestamp": "Aug 15 PostgreSQL pytest"
    }

    alert = create_alert(detection)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            alert_id,
            severity,
            title,
            source_ip,
            threat_type,
            status
        FROM alerts
        WHERE alert_id = %s;
        """,
        (alert["alert_id"],)
    )

    row = cursor.fetchone()

    cursor.close()
    connection.close()

    assert row is not None
    assert row[0] == alert["alert_id"]
    assert row[1] == "Medium"
    assert row[2] == "PYTEST PostgreSQL Alert"
    assert row[3] == "192.168.1.22"
    assert row[4] == "SSH Brute Force"
    assert row[5] == "Open"