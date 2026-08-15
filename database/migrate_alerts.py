import json
import os
import psycopg2

from database.db_connection import get_connection

# =========================================================
# FILE PATH
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

ALERT_FILE = os.path.join(
    PROJECT_ROOT,
    "output",
    "alerts.json"
)

# =========================================================
# LOAD JSON ALERTS
# =========================================================

with open(
    ALERT_FILE,
    "r",
    encoding="utf-8"
) as file:

    alerts = json.load(file)

# =========================================================
# CONNECT DATABASE
# =========================================================

connection = get_connection()

cursor = connection.cursor()

inserted = 0

# =========================================================
# INSERT ALERTS
# =========================================================

for alert in alerts:

    try:

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
                %s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s::jsonb,
                %s::jsonb,
                %s::jsonb,
                %s,%s
            )
            ON CONFLICT (alert_id)
            DO NOTHING
            """,
            (
                alert.get("alert_id"),
                alert.get("severity"),
                alert.get("title"),
                alert.get("description"),
                alert.get("source_ip"),
                alert.get("threat_type"),
                alert.get("timestamp"),
                alert.get("status"),
                alert.get("analyst_notes", ""),

                json.dumps(
                    alert.get(
                        "mitre_attack",
                        {}
                    )
                ),

                json.dumps(
                    alert.get(
                        "ioc_enrichment",
                        {}
                    )
                ),

                json.dumps(
                    alert.get(
                        "investigation_history",
                        []
                    )
                ),

                alert.get(
                    "response_action"
                ),

                alert.get(
                    "response_status"
                )
            )
        )

        inserted += 1

    except Exception as error:

        print(
            f"Error inserting "
            f"{alert.get('alert_id')}: "
            f"{error}"
        )

connection.commit()

cursor.close()

connection.close()

print(
    f"Migration complete. "
    f"{inserted} alerts processed."
)