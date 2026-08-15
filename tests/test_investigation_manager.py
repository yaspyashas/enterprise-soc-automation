import pytest

from alert_manager.alert_manager import create_alert
from investigation.investigation_manager import (
    start_investigation,
    contain_alert,
    resolve_alert
)
from response.response_manager import block_source_ip
from database.db_connection import get_connection


# =========================================================
# CREATE TEST ALERT
# =========================================================

@pytest.fixture
def test_alert():

    alert = create_alert({
        "severity": "High",
        "title": "PYTEST Investigation Workflow",
        "description": "Automated PostgreSQL investigation workflow test",
        "source_ip": "192.168.1.250",
        "threat_type": "SSH Brute Force",
        "timestamp": "pytest"
    })

    yield alert

    # -----------------------------------------------------
    # Cleanup PostgreSQL test alert
    # -----------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM alerts
        WHERE alert_id = %s;
        """,
        (alert["alert_id"],)
    )

    connection.commit()

    cursor.close()
    connection.close()


# =========================================================
# TEST 1 — START INVESTIGATION
# =========================================================

def test_start_investigation(test_alert):

    alert_id = test_alert["alert_id"]

    result = start_investigation(alert_id)

    assert result["success"] is True
    assert result["alert"]["status"] == "Investigating"

    history = result["alert"]["investigation_history"]

    assert any(
        item["action"] == "Investigation Started"
        for item in history
    )


# =========================================================
# TEST 2 — CONTAIN ALERT
# =========================================================

def test_contain_alert(test_alert):

    alert_id = test_alert["alert_id"]

    start_result = start_investigation(alert_id)

    assert start_result["success"] is True

    result = contain_alert(
        alert_id,
        "Pytest containment completed."
    )

    assert result["success"] is True
    assert result["alert"]["status"] == "Contained"

    history = result["alert"]["investigation_history"]

    assert any(
        item["action"] == "Alert Contained"
        for item in history
    )


# =========================================================
# TEST 3 — RESOLVE BEFORE RESPONSE
# =========================================================

def test_resolve_before_response_fails(test_alert):

    alert_id = test_alert["alert_id"]

    start_result = start_investigation(alert_id)

    assert start_result["success"] is True

    contain_result = contain_alert(
        alert_id,
        "Pytest containment completed."
    )

    assert contain_result["success"] is True

    result = resolve_alert(alert_id)

    assert result["success"] is False

    assert "Response must be executed first" in result["message"]


# =========================================================
# TEST 4 — EXECUTE RESPONSE
# =========================================================

def test_execute_response(test_alert):

    alert_id = test_alert["alert_id"]

    start_result = start_investigation(alert_id)

    assert start_result["success"] is True

    contain_result = contain_alert(
        alert_id,
        "Pytest containment completed."
    )

    assert contain_result["success"] is True

    result = block_source_ip(alert_id)

    assert result["success"] is True
    assert result["response_action"] == "Block Source IP"
    assert result["response_status"] == "Executed"

    assert result["alert"]["status"] == "Response Executed"


# =========================================================
# TEST 5 — COMPLETE WORKFLOW
# =========================================================

def test_complete_investigation_workflow(test_alert):

    alert_id = test_alert["alert_id"]

    # -----------------------------------------------------
    # Open → Investigating
    # -----------------------------------------------------

    result = start_investigation(alert_id)

    assert result["success"] is True
    assert result["alert"]["status"] == "Investigating"

    # -----------------------------------------------------
    # Investigating → Contained
    # -----------------------------------------------------

    result = contain_alert(
        alert_id,
        "Full pytest containment completed."
    )

    assert result["success"] is True
    assert result["alert"]["status"] == "Contained"

    # -----------------------------------------------------
    # Contained → Response Executed
    # -----------------------------------------------------

    result = block_source_ip(alert_id)

    assert result["success"] is True
    assert result["alert"]["status"] == "Response Executed"

    # -----------------------------------------------------
    # Response Executed → Resolved
    # -----------------------------------------------------

    result = resolve_alert(
        alert_id,
        "Pytest workflow completed successfully."
    )

    assert result["success"] is True
    assert result["alert"]["status"] == "Resolved"

    # -----------------------------------------------------
    # Verify investigation history
    # -----------------------------------------------------

    history = result["alert"]["investigation_history"]

    actions = [
        item["action"]
        for item in history
    ]

    assert "Alert Created" in actions
    assert "Investigation Started" in actions
    assert "Alert Contained" in actions
    assert "Response Executed" in actions
    assert "Alert Resolved" in actions