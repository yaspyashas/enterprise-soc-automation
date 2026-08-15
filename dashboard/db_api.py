import json

from datetime import datetime

from database.db_connection import get_connection


ALERT_COLUMNS = [
    "alert_id",
    "severity",
    "title",
    "description",
    "source_ip",
    "threat_type",
    "timestamp",
    "status",
    "analyst_notes",
    "mitre_attack",
    "ioc_enrichment",
    "investigation_history",
    "response_action",
    "response_status",
    "created_at",
    "updated_at"
]


ALERT_SELECT = """
    SELECT
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
        response_status,
        created_at,
        updated_at
    FROM alerts
"""


def row_to_alert(row):

    return dict(
        zip(
            ALERT_COLUMNS,
            row
        )
    )


def get_all_alerts():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        ALERT_SELECT + """
        ORDER BY id;
        """
    )

    rows = cursor.fetchall()

    alerts = [
        row_to_alert(row)
        for row in rows
    ]

    cursor.close()
    connection.close()

    return alerts


def start_investigation(alert_id):

    connection = get_connection()
    cursor = connection.cursor()

    # Find alert
    cursor.execute(
        """
        SELECT status, investigation_history
        FROM alerts
        WHERE alert_id = %s;
        """,
        (alert_id,)
    )

    row = cursor.fetchone()

    if row is None:

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": f"Alert {alert_id} not found."
        }

    current_status = row[0]
    history = row[1] or []

    # Validate workflow
    if current_status != "Open":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} cannot start "
                f"investigation from status "
                f"{current_status}."
            )
        }

    # Create history entry
    history.append({
        "action": "Investigation Started",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "details": "SOC analyst started investigation."
    })

    # Update PostgreSQL
    cursor.execute(
        """
        UPDATE alerts
        SET
            status = 'Investigating',
            investigation_history = %s::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s;
        """,
        (
            json.dumps(history),
            alert_id
        )
    )

    connection.commit()

    # Retrieve updated alert
    cursor.execute(
        ALERT_SELECT + """
        WHERE alert_id = %s;
        """,
        (alert_id,)
    )

    updated_row = cursor.fetchone()

    alert = row_to_alert(updated_row)

    cursor.close()
    connection.close()

    return {
        "success": True,
        "message": (
            f"Investigation started for "
            f"{alert_id}."
        ),
        "alert": alert
    }


def contain_alert(alert_id, details=""):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT status, investigation_history
        FROM alerts
        WHERE alert_id = %s;
        """,
        (alert_id,)
    )

    row = cursor.fetchone()

    if row is None:

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": f"Alert {alert_id} not found."
        }

    current_status = row[0]
    history = row[1] or []

    if current_status != "Investigating":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} cannot be contained "
                f"from status {current_status}."
            )
        }

    history.append({
        "action": "Alert Contained",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "details": (
            details
            or "Threat containment action completed."
        )
    })

    cursor.execute(
        """
        UPDATE alerts
        SET
            status = 'Contained',
            investigation_history = %s::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s;
        """,
        (
            json.dumps(history),
            alert_id
        )
    )

    connection.commit()

    cursor.execute(
        ALERT_SELECT + """
        WHERE alert_id = %s;
        """,
        (alert_id,)
    )

    updated_row = cursor.fetchone()

    alert = row_to_alert(updated_row)

    cursor.close()
    connection.close()

    return {
        "success": True,
        "message": (
            f"Alert {alert_id} marked as Contained."
        ),
        "alert": alert
    }