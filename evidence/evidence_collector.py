import os
import json
from datetime import datetime


# =====================================================
# PROJECT ROOT
# =====================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =====================================================
# OUTPUT DIRECTORIES
# =====================================================

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "output"
)

EVIDENCE_DIR = os.path.join(
    OUTPUT_DIR,
    "evidence"
)

os.makedirs(
    EVIDENCE_DIR,
    exist_ok=True
)


# =====================================================
# CURRENT TIMESTAMP
# =====================================================

def current_timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# =====================================================
# COLLECT EVIDENCE
# =====================================================

def collect_evidence(alert):

    # -------------------------------------------------
    # Validate alert
    # -------------------------------------------------

    if not isinstance(alert, dict):

        return {
            "success": False,
            "message": "Invalid alert supplied.",
            "evidence_file": "",
            "evidence": {}
        }


    # -------------------------------------------------
    # Alert information
    # -------------------------------------------------

    alert_id = alert.get(
        "alert_id",
        "UNKNOWN"
    )

    title = alert.get(
        "title",
        "Unknown Alert"
    )

    severity = alert.get(
        "severity",
        "Unknown"
    )

    threat_type = alert.get(
        "threat_type",
        "Unknown"
    )


    # -------------------------------------------------
    # Evidence timestamp
    # -------------------------------------------------

    collected_at = current_timestamp()


    # -------------------------------------------------
    # Build evidence package
    # -------------------------------------------------

    evidence_data = {

        "evidence_package": {

            "package_id":
                f"EVIDENCE-{alert_id}",

            "alert_id":
                alert_id,

            "collected_at":
                collected_at,

            "collector":
                "SOC Automation Evidence Collector",

            "collection_status":
                "Successful"
        },


        "incident": {

            "alert_id":
                alert_id,

            "title":
                title,

            "severity":
                severity,

            "threat_type":
                threat_type,

            "description":
                alert.get(
                    "description",
                    ""
                ),

            "status":
                alert.get(
                    "status",
                    "Open"
                ),

            "timestamp":
                alert.get(
                    "timestamp",
                    ""
                )
        },


        "network": {

            "source_ip":
                alert.get(
                    "source_ip",
                    "N/A"
                )
        },


        "ioc_enrichment":
            alert.get(
                "ioc_enrichment",
                {}
            ),


        "mitre_attack":
            alert.get(
                "mitre_attack",
                {}
            ),


        "investigation_history":
            alert.get(
                "investigation_history",
                []
            )
    }


    # -------------------------------------------------
    # Evidence filename
    # -------------------------------------------------

    evidence_filename = (
        f"{alert_id}_evidence.json"
    )


    evidence_path = os.path.join(
        EVIDENCE_DIR,
        evidence_filename
    )


    # -------------------------------------------------
    # Write evidence file
    # -------------------------------------------------

    try:

        with open(
            evidence_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                evidence_data,
                file,
                indent=4,
                ensure_ascii=False
            )

    except Exception as error:

        return {

            "success":
                False,

            "message":
                (
                    "Evidence collection failed: "
                    f"{str(error)}"
                ),

            "evidence_file":
                "",

            "evidence":
                {}
        }


    # -------------------------------------------------
    # Return result
    # -------------------------------------------------

    return {

        "success":
            True,

        "message":
            "Investigation evidence package created.",

        "evidence_file":
            evidence_filename,

        "evidence_path":
            evidence_path,

        "collected_at":
            collected_at,

        "evidence":
            evidence_data
    }