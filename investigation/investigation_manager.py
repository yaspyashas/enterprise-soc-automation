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
# FIND ALERT
# =========================================================

def find_alert(
    alerts,
    alert_id
):

    for alert in alerts:

        if alert.get(
            "alert_id"
        ) == alert_id:

            return alert

    return None


# =========================================================
# ADD INVESTIGATION HISTORY
# =========================================================

def add_investigation_history(
    alert,
    action,
    details=""
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
# START INVESTIGATION
# =========================================================

def start_investigation(alert_id):

    connection = get_connection()
    cursor = connection.cursor()

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

    current_status = alert.get(
        "status",
        "Open"
    )

    if current_status != "Open":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} "
                f"cannot start investigation "
                f"from status {current_status}."
            )
        }

    history = alert.get(
        "investigation_history"
    ) or []

    history.append({
        "action": "Investigation Started",
        "timestamp": current_timestamp(),
        "details": "SOC analyst started investigation."
    })

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
            f"Investigation started for "
            f"{alert_id}."
        ),
        "alert": alert
    }


# =========================================================
# CONTAIN ALERT
# =========================================================

def contain_alert(
    alert_id,
    details=""
):

    connection = get_connection()
    cursor = connection.cursor()

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

    current_status = alert.get(
        "status",
        "Open"
    )

    if current_status != "Investigating":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} "
                f"cannot be contained from "
                f"status {current_status}."
            )
        }

    history = alert.get(
        "investigation_history"
    ) or []

    history.append({
        "action": "Alert Contained",
        "timestamp": current_timestamp(),
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
            f"Alert {alert_id} "
            f"marked as Contained."
        ),
        "alert": alert
    }

# =========================================================
# RESOLVE ALERT
# =========================================================

def resolve_alert(
    alert_id,
    details=""
):

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
    # Validate response execution
    # -----------------------------------------------------

    current_status = alert.get(
        "status",
        "Open"
    )

    if current_status != "Response Executed":

        cursor.close()
        connection.close()

        return {
            "success": False,
            "message": (
                f"Alert {alert_id} cannot be resolved "
                f"from status {current_status}. "
                f"Response must be executed first."
            )
        }

    # -----------------------------------------------------
    # Update investigation history
    # -----------------------------------------------------

    history = alert.get(
        "investigation_history"
    ) or []

    history.append({
        "action": "Alert Resolved",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "details": (
            details
            or "Investigation completed and alert resolved."
        )
    })

    # -----------------------------------------------------
    # Update PostgreSQL
    # -----------------------------------------------------

    cursor.execute(
        """
        UPDATE alerts
        SET
            status = 'Resolved',
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

    # -----------------------------------------------------
    # Get updated alert
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
            f"Alert {alert_id} marked as Resolved."
        ),
        "alert": alert
    }
