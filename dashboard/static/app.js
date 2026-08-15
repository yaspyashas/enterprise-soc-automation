async function loadDashboard() {

    try {

        const summaryResponse =
            await fetch("/api/dashboard/summary");

        const summaryData =
            await summaryResponse.json();

        if (!summaryData.success) {
            throw new Error("Unable to load dashboard summary");
        }

        const summary =
            summaryData.summary;


        // =====================================================
        // SUMMARY CARDS
        // =====================================================

        document.getElementById("total-alerts").textContent =
            summary.total_alerts;

        document.getElementById("high-severity").textContent =
            summary.high_severity;

        document.getElementById("investigating").textContent =
            summary.investigating;

        document.getElementById("resolved").textContent =
            summary.resolved;


        // =====================================================
        // STATUS COUNTS
        // =====================================================

        document.getElementById("open-count").textContent =
            summary.open;

        document.getElementById("investigating-count").textContent =
            summary.investigating;

        document.getElementById("contained-count").textContent =
            summary.contained;

        document.getElementById("response-count").textContent =
            summary.response_executed;

        document.getElementById("resolved-count").textContent =
            summary.resolved;


        // =====================================================
        // LOAD ALERTS
        // =====================================================

        const alertsResponse =
            await fetch("/api/alerts");

        const alertsData =
            await alertsResponse.json();

        if (!alertsData.success) {
            throw new Error("Unable to load alerts");
        }

        const alerts =
            alertsData.alerts || [];

        document.getElementById("alert-count").textContent =
            `${alerts.length} alerts`;


        const table =
            document.getElementById("alerts-table");

        table.innerHTML = "";


        if (alerts.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6" class="loading">
                        No alerts found.
                    </td>
                </tr>
            `;

            return;
        }


        // =====================================================
        // CREATE ALERT ROWS
        // =====================================================

        alerts.forEach(alert => {

            const row =
                document.createElement("tr");

            const severity =
                String(alert.severity || "")
                    .toLowerCase();

            const status =
                String(alert.status || "")
                    .toLowerCase()
                    .replace(/\s+/g, "-");


            row.innerHTML = `

                <td>
                    <button
                        class="alert-id-button"
                        onclick="openAlert('${escapeJs(alert.alert_id)}')"
                    >
                        ${escapeHtml(alert.alert_id)}
                    </button>
                </td>

                <td>
                    <span class="severity-${severity}">
                        ${escapeHtml(alert.severity)}
                    </span>
                </td>

                <td>
                    ${escapeHtml(alert.title)}
                </td>

                <td>
                    ${escapeHtml(alert.source_ip || "-")}
                </td>

                <td>
                    ${escapeHtml(alert.threat_type || "-")}
                </td>

                <td>
                    <span class="status-${status}">
                        ${escapeHtml(alert.status)}
                    </span>
                </td>

            `;

            table.appendChild(row);

        });


    } catch (error) {

        console.error(
            "Dashboard loading error:",
            error
        );

        document.getElementById(
            "alerts-table"
        ).innerHTML = `
            <tr>
                <td colspan="6" class="loading">
                    Failed to load dashboard data.
                </td>
            </tr>
        `;
    }
}


/*
 * =========================================================
 * OPEN ALERT
 * =========================================================
 */

async function openAlert(alertId) {

    try {

        console.log(
            "Opening alert:",
            alertId
        );


        const response =
            await fetch(
                `/api/alerts/${encodeURIComponent(alertId)}`
            );


        const data =
            await response.json();


        if (!response.ok || !data.success) {

            throw new Error(
                data.message ||
                `Unable to load alert ${alertId}`
            );

        }


        showAlertDetails(
            data.alert
        );


    } catch (error) {

        console.error(
            "Alert loading error:",
            error
        );

        alert(
            `Unable to open ${alertId}.\n\n${error.message}`
        );
    }
}


/*
 * =========================================================
 * ALERT DETAILS MODAL
 * =========================================================
 */

function showAlertDetails(alert) {

    let modal =
        document.getElementById(
            "alert-details-modal"
        );


    if (!modal) {

        modal =
            document.createElement("div");

        modal.id =
            "alert-details-modal";

        modal.className =
            "alert-modal";


        document.body.appendChild(
            modal
        );
    }


    const severity =
        String(alert.severity || "")
            .toLowerCase();


    const status =
        String(alert.status || "")
            .toLowerCase()
            .replace(/\s+/g, "-");


    const investigationHistory =
        Array.isArray(
            alert.investigation_history
        )
            ? alert.investigation_history
            : [];


    let historyHtml =
        "<p>No investigation history.</p>";


    if (investigationHistory.length > 0) {

        historyHtml =
            investigationHistory
                .map(entry => {

                    return `
                        <div class="history-entry">

                            <strong>
                                ${escapeHtml(
                                    entry.action || "Action"
                                )}
                            </strong>

                            <span>
                                ${escapeHtml(
                                    entry.timestamp || "-"
                                )}
                            </span>

                            <p>
                                ${escapeHtml(
                                    entry.details || "-"
                                )}
                            </p>

                        </div>
                    `;

                })
                .join("");
    }


    modal.innerHTML = `

        <div class="alert-modal-backdrop"
             onclick="closeAlertDetails()">
        </div>


        <div class="alert-modal-content">

            <div class="alert-modal-header">

                <div>

                    <span class="modal-label">
                        SECURITY ALERT
                    </span>

                    <h2>
                        ${escapeHtml(
                            alert.alert_id
                        )}
                    </h2>

                    <p>
                        ${escapeHtml(
                            alert.title || "-"
                        )}
                    </p>

                </div>


                <button
                    class="modal-close"
                    onclick="closeAlertDetails()"
                >
                    ×
                </button>

            </div>


            <!-- STATUS -->

            <div class="alert-detail-status">

                <span>
                    Severity
                </span>

                <strong class="severity-${severity}">
                    ${escapeHtml(
                        alert.severity || "-"
                    )}
                </strong>


                <span>
                    Status
                </span>

                <strong class="status-${status}">
                    ${escapeHtml(
                        alert.status || "-"
                    )}
                </strong>

            </div>


            <!-- ALERT INFORMATION -->

            <div class="detail-section">

                <h3>
                    Alert Information
                </h3>


                <div class="detail-grid">

                    <div>
                        <span>Alert ID</span>
                        <strong>
                            ${escapeHtml(
                                alert.alert_id
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Threat Type</span>
                        <strong>
                            ${escapeHtml(
                                alert.threat_type || "-"
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Source IP</span>
                        <strong>
                            ${escapeHtml(
                                alert.source_ip || "-"
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Timestamp</span>
                        <strong>
                            ${escapeHtml(
                                alert.timestamp || "-"
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Response Action</span>
                        <strong>
                            ${escapeHtml(
                                alert.response_action || "-"
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Response Status</span>
                        <strong>
                            ${escapeHtml(
                                alert.response_status || "-"
                            )}
                        </strong>
                    </div>

                </div>

            </div>


            <!-- DESCRIPTION -->

            <div class="detail-section">

                <h3>
                    Description
                </h3>

                <p class="detail-description">
                    ${escapeHtml(
                        alert.description || "-"
                    )}
                </p>

            </div>


            <!-- MITRE -->

            <div class="detail-section">

                <h3>
                    MITRE ATT&CK
                </h3>

                <pre class="json-box">${escapeHtml(
                    formatJson(alert.mitre_attack)
                )}</pre>

            </div>


            <!-- IOC -->

            <div class="detail-section">

                <h3>
                    IOC Enrichment
                </h3>

                <pre class="json-box">${escapeHtml(
                    formatJson(alert.ioc_enrichment)
                )}</pre>

            </div>


            <!-- INVESTIGATION HISTORY -->

            <div class="detail-section">

                <h3>
                    Investigation History
                </h3>

                <div class="history-container">

                    ${historyHtml}

                </div>

            </div>


            <!-- ANALYST NOTES -->

            <div class="detail-section">

                <h3>
                    Analyst Notes
                </h3>

                <p class="detail-description">
                    ${escapeHtml(
                        alert.analyst_notes || "-"
                    )}
                </p>

            </div>


            <!-- ACTIONS -->

            <div class="alert-actions">

                <button
                    class="action-button investigate"
                    onclick="investigateAlert('${escapeJs(alert.alert_id)}')"
                >
                    Start Investigation
                </button>


                <button
                    class="action-button contain"
                    onclick="containAlert('${escapeJs(alert.alert_id)}')"
                >
                    Contain Alert
                </button>


                <button
                    class="action-button evidence"
                    onclick="collectEvidence('${escapeJs(alert.alert_id)}')"
                >
                    Collect Evidence
                </button>


                <button
                    class="action-button response"
                    onclick="executeResponse('${escapeJs(alert.alert_id)}')"
                >
                    Execute Response
                </button>


                <button
                    class="action-button resolve"
                    onclick="resolveAlert('${escapeJs(alert.alert_id)}')"
                >
                    Resolve Alert
                </button>

            </div>

        </div>
    `;


    modal.classList.add(
        "visible"
    );
}


/*
 * =========================================================
 * CLOSE ALERT DETAILS
 * =========================================================
 */

function closeAlertDetails() {

    const modal =
        document.getElementById(
            "alert-details-modal"
        );


    if (modal) {

        modal.classList.remove(
            "visible"
        );
    }
}


/*
 * =========================================================
 * START INVESTIGATION
 * =========================================================
 */

async function investigateAlert(alertId) {

    await executeAlertAction(
        `/api/alerts/${encodeURIComponent(alertId)}/investigate`,
        "Investigation started"
    );
}


/*
 * =========================================================
 * CONTAIN ALERT
 * =========================================================
 */

async function containAlert(alertId) {

    await executeAlertAction(
        `/api/alerts/${encodeURIComponent(alertId)}/contain`,
        "Alert contained"
    );
}


/*
 * =========================================================
 * COLLECT EVIDENCE
 * =========================================================
 */

async function collectEvidence(alertId) {

    await executeAlertAction(
        `/api/alerts/${encodeURIComponent(alertId)}/evidence`,
        "Evidence collected"
    );
}


/*
 * =========================================================
 * EXECUTE RESPONSE
 * =========================================================
 */

async function executeResponse(alertId) {

    await executeAlertAction(
        `/api/alerts/${encodeURIComponent(alertId)}/response`,
        "Response executed"
    );
}


/*
 * =========================================================
 * RESOLVE ALERT
 * =========================================================
 */

async function resolveAlert(alertId) {

    await executeAlertAction(
        `/api/alerts/${encodeURIComponent(alertId)}/resolve`,
        "Alert resolved"
    );
}


/*
 * =========================================================
 * GENERIC ALERT ACTION
 * =========================================================
 */

async function executeAlertAction(
    url,
    successMessage
) {

    try {

        const response =
            await fetch(
                url,
                {
                    method: "POST"
                }
            );


        const data =
            await response.json();


        if (!response.ok || !data.success) {

            throw new Error(
                data.message ||
                "Action failed"
            );
        }


        alert(
            successMessage
        );


        closeAlertDetails();


        await loadDashboard();


    } catch (error) {

        console.error(
            "Alert action error:",
            error
        );


        alert(
            `Action failed.\n\n${error.message}`
        );
    }
}


/*
 * =========================================================
 * JSON FORMATTER
 * =========================================================
 */

function formatJson(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "-";
    }


    if (
        typeof value === "string"
    ) {

        try {

            return JSON.stringify(
                JSON.parse(value),
                null,
                2
            );

        } catch {

            return value;
        }
    }


    try {

        return JSON.stringify(
            value,
            null,
            2
        );

    } catch {

        return String(value);
    }
}


/*
 * =========================================================
 * HTML ESCAPE
 * =========================================================
 */

function escapeHtml(value) {

    const div =
        document.createElement("div");

    div.textContent =
        value ?? "";

    return div.innerHTML;
}


/*
 * =========================================================
 * JAVASCRIPT STRING ESCAPE
 * =========================================================
 */

function escapeJs(value) {

    return String(
        value ?? ""
    )
        .replace(/\\/g, "\\\\")
        .replace(/'/g, "\\'");
}


/*
 * =========================================================
 * LOAD DASHBOARD
 * ========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    loadDashboard
);