import pytest

from database.db_connection import get_connection
from response.response_manager import block_source_ip


TEST_ALERT_ID = "ALT-TEST-RESPONSE-0001"


def create_test_alert():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM alerts
        WHERE alert_id = %s;
        """,
        (TEST_ALERT_ID,)
    )

    cursor.execute(
        """
        INSERT INTO alerts (
            alert_id,
            severity,
            title,
            description,
            source_ip,
            threat_type,
            timestamp,
            status,
            analyst_notes,
            mitre_attack,
            ioc_enrichment,
            investigation_history,
            response_action,
            response_status
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s::jsonb,
            %s::jsonb,
            %s::jsonb,
            NULL,
            NULL
        );
        """,
        (
            TEST_ALERT_ID,
            "High",
            "SSH Brute Force Attack",
            "Test response execution",
            "192.168.1.20",
            "SSH Brute Force",
            "Aug 13 10:00:00",
            "Contained",
            "",
            "{}",
            "{}",
            "[]"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()


def remove_test_alert():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM alerts
        WHERE alert_id = %s;
        """,
        (TEST_ALERT_ID,)
    )

    connection.commit()

    cursor.close()
    connection.close()


@pytest.fixture
def response_test_alert():
    create_test_alert()

    yield

    remove_test_alert()


def get_test_alert():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            alert_id,
            status,
            source_ip,
            response_action,
            response_status
        FROM alerts
        WHERE alert_id = %s;
        """,
        (TEST_ALERT_ID,)
    )

    row = cursor.fetchone()

    cursor.close()
    connection.close()

    return row


def test_block_source_ip(response_test_alert):

    result = block_source_ip(
        TEST_ALERT_ID
    )

    assert result["success"] is True

    assert result["source_ip"] == "192.168.1.20"

    assert result["response_action"] == "Block Source IP"

    assert result["response_status"] == "Executed"

    assert result["alert"]["status"] == "Response Executed"


def test_response_persisted_in_postgresql(response_test_alert):

    block_source_ip(
        TEST_ALERT_ID
    )

    row = get_test_alert()

    assert row is not None

    alert_id, status, source_ip, response_action, response_status = row

    assert alert_id == TEST_ALERT_ID

    assert status == "Response Executed"

    assert source_ip == "192.168.1.20"

    assert response_action == "Block Source IP"

    assert response_status == "Executed"


def test_response_requires_contained_status():

    create_test_alert()

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET status = 'Investigating'
            WHERE alert_id = %s;
            """,
            (TEST_ALERT_ID,)
        )

        connection.commit()

        cursor.close()
        connection.close()

        result = block_source_ip(
            TEST_ALERT_ID
        )

        assert result["success"] is False

        assert "must be Contained" in result["message"]

    finally:
        remove_test_alert()