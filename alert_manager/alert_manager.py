import os
import json
from datetime import datetime

from mitre.mitre_mapper import map_alert_to_mitre
from threat_intelligence.ip_enricher import enrich_ip
from evidence.evidence_collector import collect_evidence
from database.db_connection import get_connection



# =========================================================
# CURRENT TIMESTAMP
# =========================================================

def current_timestamp():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )



# =========================================================
# GENERATE ALERT ID
# =========================================================

def generate_alert_id():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT alert_id
        FROM alerts
        WHERE alert_id LIKE 'ALT-%'
        ORDER BY id DESC
        LIMIT 1;
        """
    )

    row = cursor.fetchone()

    cursor.close()
    connection.close()

    if row is None:
        return "ALT-0001"

    try:
        highest_id = int(
            row[0].replace("ALT-", "")
        )
    except ValueError:
        highest_id = 0

    return f"ALT-{highest_id + 1:04d}"

# =========================================================
# CREATE ALERT
# =========================================================

def create_alert(detection):

    if not isinstance(
        detection,
        dict
    ):
        return None

    # -----------------------------------------------------
    # Generate alert ID from PostgreSQL
    # -----------------------------------------------------

    alert_id = generate_alert_id()

    timestamp = detection.get(
        "timestamp",
        current_timestamp()
    )

    # -----------------------------------------------------
    # Enrichment
    # -----------------------------------------------------

    ioc = enrich_ip(
        detection.get("source_ip")
    )

    mitre = map_alert_to_mitre(
        detection.get("threat_type")
    )

    # -----------------------------------------------------
    # Investigation history
    # -----------------------------------------------------

    history = [
        {
            "action": "Alert Created",
            "timestamp": current_timestamp(),
            "details": detection.get(
                "title",
                "Unknown Alert"
            )
        }
    ]

    # -----------------------------------------------------
    # Alert data
    # -----------------------------------------------------

    severity = detection.get(
        "severity",
        "Unknown"
    )

    title = detection.get(
        "title",
        "Unknown Alert"
    )

    description = detection.get(
        "description",
        ""
    )

    source_ip = detection.get(
        "source_ip"
    )

    threat_type = detection.get(
        "threat_type",
        "Unknown"
    )

    # -----------------------------------------------------
    # Insert into PostgreSQL
    # -----------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

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
            'Open',
            '',
            %s::jsonb,
            %s::jsonb,
            %s::jsonb,
            NULL,
            NULL
        );
        """,
        (
            alert_id,
            severity,
            title,
            description,
            source_ip,
            threat_type,
            timestamp,
            json.dumps(mitre),
            json.dumps(ioc),
            json.dumps(history)
        )
    )

    connection.commit()

    # -----------------------------------------------------
    # Get the newly created alert
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

    alert = dict(
        zip(columns, row)
    )

    cursor.close()
    connection.close()

    # -----------------------------------------------------
    # Evidence collection
    # -----------------------------------------------------

    collect_evidence(
        alert
    )

    return alert
