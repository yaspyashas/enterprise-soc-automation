import os
import json
from datetime import datetime
from database.db_connection import get_connection

# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =========================================================
# OUTPUT DIRECTORY
# =========================================================

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "output"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)



# =========================================================
# CURRENT TIMESTAMP
# =========================================================

def current_timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )




# =========================================================
# ADD INVESTIGATION HISTORY
# =========================================================

def add_response_history(
    alert,
    action,
    details
):

    if "investigation_history" not in alert:

        alert["investigation_history"] = []

    alert["investigation_history"].append(
        {
            "action": action,
            "timestamp": current_timestamp(),
            "details": details
        }
    )


# =========================================================
# BLOCK SOURCE IP
# =========================================================

def block_source_ip(alert_id):

    connection = get_connection()
    cursor = connection.cursor()

    # -----------------------------------------------------
    # Get alert from PostgreSQL
    # -----------------------------------------------------

    cursor.execute(
        """
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

    columns = [
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

    alert = dict(zip(columns, row))

    # -----------------------------------------------------
    # Validate alert status
    # -----------------------------------------------------

    current_status = alert.get("status", "Unknown")

    if current_status != "Contained":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} must be Contained "
                f"before response execution. "
                f"Current status: {current_status}"
            )
        }

    # -----------------------------------------------------
    # Get source IP
    # -----------------------------------------------------

    source_ip = alert.get("source_ip")

    if not source_ip:

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"No source IP available "
                f"for alert {alert_id}."
            )
        }

    # -----------------------------------------------------
    # Simulated response
    # -----------------------------------------------------

    response_action = "Block Source IP"
    response_status = "Executed"

    # -----------------------------------------------------
    # Update investigation history
    # -----------------------------------------------------

    history = alert.get("investigation_history") or []

    history.append({
        "action": "Response Executed",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "details": (
            f"Simulated blocking of source IP "
            f"{source_ip}."
        )
    })

    # -----------------------------------------------------
    # Update PostgreSQL
    # -----------------------------------------------------

    cursor.execute(
        """
        UPDATE alerts
        SET
            status = 'Response Executed',
            response_action = %s,
            response_status = %s,
            investigation_history = %s::jsonb,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s;
        """,
        (
            response_action,
            response_status,
            json.dumps(history),
            alert_id
        )
    )

    connection.commit()

    # -----------------------------------------------------
    # Return updated alert
    # -----------------------------------------------------

    cursor.execute(
        """
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
        WHERE alert_id = %s;
        """,
        (alert_id,)
    )

    updated_row = cursor.fetchone()

    alert = dict(
        zip(columns, updated_row)
    )

    cursor.close()
    connection.close()

    return {
        "success": True,
        "message": (
            f"Source IP {source_ip} "
            f"blocked successfully."
        ),
        "response_action": response_action,
        "response_status": response_status,
        "source_ip": source_ip,
        "alert": alert
    }
