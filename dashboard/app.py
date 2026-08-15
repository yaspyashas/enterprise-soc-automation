import os

from flask import Flask, jsonify, render_template

from dashboard.db_api import (
    get_all_alerts,
    start_investigation,
    contain_alert
)

from investigation.investigation_manager import (
    resolve_alert
)

from response.response_manager import (
    block_source_ip
)

from evidence.evidence_collector import (
    collect_evidence
)

from database.db_connection import (
    get_connection
)

# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

@app.route("/")
def dashboard():

    return render_template(
        "index.html"
    )

# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =========================================================
# LOAD ALERTS FROM POSTGRESQL
# =========================================================

def load_alerts():

    try:

        return get_all_alerts()

    except Exception as e:

        print(
            f"Error loading alerts from PostgreSQL: {e}"
        )

        return []

# =========================================================
# HEALTH CHECK
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    return jsonify({
        "status": "ok",
        "service": "Enterprise SOC Automation",
        "version": "1.0.0"
    })





# =========================================================
# START INVESTIGATION
# =========================================================

@app.route(
    "/api/alerts/<alert_id>/investigate",
    methods=["POST"]
)
def investigate_alert(alert_id):

    result = start_investigation(alert_id)

    status_code = 200 if result.get("success") else 400

    return jsonify(result), status_code




# =========================================================
# EXECUTE RESPONSE
# =========================================================

@app.route(
    "/api/alerts/<alert_id>/response",
    methods=["POST"]
)
def execute_response(alert_id):

    result = block_source_ip(alert_id)

    status_code = 200 if result.get("success") else 400

    return jsonify(result), status_code


# =========================================================
# RESOLVE ALERT
# =========================================================

@app.route(
    "/api/alerts/<alert_id>/resolve",
    methods=["POST"]
)
def resolve_alert_api(alert_id):

    result = resolve_alert(alert_id)

    status_code = 200 if result.get("success") else 400

    return jsonify(result), status_code

# =========================================================
# COLLECT INVESTIGATION EVIDENCE
# =========================================================

@app.route(
    "/api/alerts/<alert_id>/evidence",
    methods=["POST"]
)
def collect_alert_evidence(alert_id):

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

        return jsonify({
            "success": False,
            "message": f"Alert {alert_id} not found."
        }), 404

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

    result = collect_evidence(alert)

    status_code = (
        200
        if result.get("success")
        else 400
    )

    return jsonify(result), status_code

# =========================================================
# DASHBOARD SUMMARY
# =========================================================

@app.route(
    "/api/dashboard/summary",
    methods=["GET"]
)
def dashboard_summary():

    alerts = load_alerts()

    summary = {
        "total_alerts": len(alerts),
        "open": 0,
        "investigating": 0,
        "contained": 0,
        "response_executed": 0,
        "resolved": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0
    }

    for alert in alerts:

        status = alert.get(
            "status",
            "Unknown"
        )

        severity = alert.get(
            "severity",
            "Unknown"
        )

        # ---------------------------------------------
        # Status count
        # ---------------------------------------------

        if status == "Open":
            summary["open"] += 1

        elif status == "Investigating":
            summary["investigating"] += 1

        elif status == "Contained":
            summary["contained"] += 1

        elif status == "Response Executed":
            summary["response_executed"] += 1

        elif status == "Resolved":
            summary["resolved"] += 1

        # ---------------------------------------------
        # Severity count
        # ---------------------------------------------

        if severity == "High":
            summary["high_severity"] += 1

        elif severity == "Medium":
            summary["medium_severity"] += 1

        elif severity == "Low":
            summary["low_severity"] += 1

    return jsonify({
        "success": True,
        "summary": summary
    })

@app.route("/api/alerts", methods=["GET"])
def api_get_alerts():

    try:

        alerts = get_all_alerts()

        return jsonify({
            "success": True,
            "count": len(alerts),
            "alerts": alerts
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

@app.route("/api/alerts/<alert_id>", methods=["GET"])
def api_get_alert(alert_id):

    try:
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

        cursor.close()
        connection.close()

        if row is None:
            return jsonify({
                "success": False,
                "message": f"Alert {alert_id} not found."
            }), 404

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

        return jsonify({
            "success": True,
            "alert": alert
        })

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500



@app.route(
    "/api/alerts/<alert_id>/contain",
    methods=["POST"]
)
def contain_alert_api(alert_id):

    try:

        result = contain_alert(
            alert_id
        )

        if not result["success"]:

            return jsonify(result), 400

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

# =========================================================
# RUN FLASK
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )