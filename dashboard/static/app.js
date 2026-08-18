/*
 * =========================================================
 * ENTERPRISE SOC DASHBOARD
 * =========================================================
 */

let dashboardAlerts = [];

let currentSortColumn = null;
let currentSortDirection = "asc";


/*
 * =========================================================
 * LOAD DASHBOARD
 * =========================================================
 */

async function loadDashboard() {

    try {

        console.log("Loading dashboard...");


        // =====================================================
        // SHOW LOADING STATE
        // =====================================================

        const table =
            document.getElementById("alerts-table");

        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="6" class="loading">
                        Loading alerts...
                    </td>
                </tr>
            `;
        }


        // =====================================================
        // LOAD DASHBOARD SUMMARY
        // =====================================================

        const summaryResponse =
            await fetch(
                "/api/dashboard/summary",
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    },
                    cache: "no-store"
                }
            );


        if (!summaryResponse.ok) {

            throw new Error(
                `Dashboard summary request failed: ${summaryResponse.status}`
            );
        }


        const summaryData =
            await summaryResponse.json();


        if (!summaryData.success) {

            throw new Error(
                summaryData.message ||
                "Unable to load dashboard summary"
            );
        }


        const summary =
            summaryData.summary || {};


        console.log(
            "Dashboard summary:",
            summary
        );


        // =====================================================
        // SUMMARY CARDS
        // =====================================================

        setText(
            "total-alerts",
            summary.total_alerts ?? 0
        );

        setText(
            "high-severity",
            summary.high_severity ?? 0
        );

        setText(
            "investigating",
            summary.investigating ?? 0
        );

        setText(
            "resolved",
            summary.resolved ?? 0
        );


        // =====================================================
        // STATUS COUNTS
        // =====================================================

        setText(
            "open-count",
            summary.open ?? 0
        );

        setText(
            "investigating-count",
            summary.investigating ?? 0
        );

        setText(
            "contained-count",
            summary.contained ?? 0
        );

        setText(
            "response-count",
            summary.response_executed ?? 0
        );

        setText(
            "resolved-count",
            summary.resolved ?? 0
        );


        // =====================================================
        // LOAD ALERTS
        // =====================================================

        const alertsResponse =
            await fetch(
                "/api/alerts",
                {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    },
                    cache: "no-store"
                }
            );


        if (!alertsResponse.ok) {

            throw new Error(
                `Alerts request failed: ${alertsResponse.status}`
            );
        }


        const alertsData =
            await alertsResponse.json();


        if (!alertsData.success) {

            throw new Error(
                alertsData.message ||
                "Unable to load alerts"
            );
        }


        const alerts =
            Array.isArray(alertsData.alerts)
                ? alertsData.alerts
                : [];


        dashboardAlerts =
            alerts;


        console.log(
            `Loaded ${dashboardAlerts.length} alerts`
        );


        // =====================================================
        // RENDER ALERTS
        // =====================================================

        filterAlerts();


    } catch (error) {

        console.error(
            "Dashboard loading error:",
            error
        );


        setText(
            "total-alerts",
            "-"
        );

        setText(
            "high-severity",
            "-"
        );

        setText(
            "investigating",
            "-"
        );

        setText(
            "resolved",
            "-"
        );


        const table =
            document.getElementById(
                "alerts-table"
            );


        if (table) {

            table.innerHTML = `
                <tr>
                    <td colspan="6" class="loading">
                        Failed to load dashboard data.
                    </td>
                </tr>
            `;
        }


        const alertCount =
            document.getElementById(
                "alert-count"
            );


        if (alertCount) {

            alertCount.textContent =
                "0 alerts";
        }
    }
}


/*
 * =========================================================
 * SEARCH + FILTER ALERTS
 * =========================================================
 */

function filterAlerts() {

    const searchInput =
        document.getElementById(
            "alert-search"
        );


    const severityInput =
        document.getElementById(
            "severity-filter"
        );


    const statusInput =
        document.getElementById(
            "status-filter"
        );


    const search =
        String(
            searchInput?.value || ""
        )
            .trim()
            .toLowerCase();


    const severity =
        String(
            severityInput?.value || ""
        )
            .trim()
            .toLowerCase();


    const status =
        String(
            statusInput?.value || ""
        )
            .trim()
            .toLowerCase();


    const filteredAlerts =
        dashboardAlerts.filter(
            alert => {


                // =================================================
                // SEARCH
                // =================================================

                const searchableText = [

                    alert.alert_id,

                    alert.source_ip,

                    alert.title,

                    alert.threat_type,

                    alert.description,

                    alert.response_action,

                    alert.response_status

                ]
                    .map(
                        value =>
                            String(
                                value ?? ""
                            ).toLowerCase()
                    )
                    .join(" ");


                const matchesSearch =
                    !search ||
                    searchableText.includes(
                        search
                    );


                // =================================================
                // SEVERITY
                // =================================================

                const alertSeverity =
                    String(
                        alert.severity ?? ""
                    )
                        .trim()
                        .toLowerCase();


                const matchesSeverity =
                    !severity ||
                    alertSeverity === severity;


                // =================================================
                // STATUS
                // =================================================

                const alertStatus =
                    String(
                        alert.status ?? ""
                    )
                        .trim()
                        .toLowerCase();


                const matchesStatus =
                    !status ||
                    alertStatus === status;


                return (
                    matchesSearch &&
                    matchesSeverity &&
                    matchesStatus
                );
            }
        );


    renderAlerts(
        filteredAlerts
    );
}


/*
 * =========================================================
 * CLEAR FILTERS
 * =========================================================
 */

function clearAlertFilters() {

    const searchInput =
        document.getElementById(
            "alert-search"
        );


    const severityInput =
        document.getElementById(
            "severity-filter"
        );


    const statusInput =
        document.getElementById(
            "status-filter"
        );


    if (searchInput) {

        searchInput.value =
            "";
    }


    if (severityInput) {

        severityInput.value =
            "";
    }


    if (statusInput) {

        statusInput.value =
            "";
    }


    renderAlerts(
        dashboardAlerts
    );
}


/*
 * =========================================================
 * SORT ALERTS
 * =========================================================
 */

function sortAlerts(column) {

    if (
        currentSortColumn === column
    ) {

        currentSortDirection =
            currentSortDirection === "asc"
                ? "desc"
                : "asc";

    } else {

        currentSortColumn =
            column;

        currentSortDirection =
            "asc";
    }


    console.log(
        `Sorting ${column} ${currentSortDirection}`
    );


    filterAlerts();
}


/*
 * =========================================================
 * RENDER ALERTS
 * =========================================================
 */

function renderAlerts(alerts) {

    const table =
        document.getElementById(
            "alerts-table"
        );


    const alertCount =
        document.getElementById(
            "alert-count"
        );


    if (!table) {

        console.error(
            "alerts-table element not found"
        );

        return;
    }


    if (alertCount) {

        alertCount.textContent =
            `${alerts.length} alerts`;
    }


    table.innerHTML =
        "";


    // =====================================================
    // NO RESULTS
    // =====================================================

    if (
        !Array.isArray(alerts) ||
        alerts.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="6" class="loading">
                    No alerts match the selected filters.
                </td>
            </tr>
        `;

        return;
    }


    // =====================================================
    // SORT ALERTS
    // =====================================================

    const sortedAlerts =
        [...alerts].sort(
            (a, b) => {


                if (!currentSortColumn) {

                    return 0;
                }


                let valueA =
                    a[currentSortColumn];

                let valueB =
                    b[currentSortColumn];


                // =============================================
                // SEVERITY SORT
                // =============================================

                if (
                    currentSortColumn ===
                    "severity"
                ) {

                    const severityOrder = {

                        high: 3,

                        medium: 2,

                        low: 1

                    };


                    valueA =
                        severityOrder[
                            String(
                                valueA ?? ""
                            )
                                .toLowerCase()
                        ] || 0;


                    valueB =
                        severityOrder[
                            String(
                                valueB ?? ""
                            )
                                .toLowerCase()
                        ] || 0;
                }


                // =============================================
                // STATUS SORT
                // =============================================

                else if (
                    currentSortColumn ===
                    "status"
                ) {

                    const statusOrder = {

                        open: 1,

                        investigating: 2,

                        contained: 3,

                        "response executed": 4,

                        resolved: 5

                    };


                    valueA =
                        statusOrder[
                            String(
                                valueA ?? ""
                            )
                                .toLowerCase()
                        ] || 0;


                    valueB =
                        statusOrder[
                            String(
                                valueB ?? ""
                            )
                                .toLowerCase()
                        ] || 0;
                }


                // =============================================
                // ALERT ID SORT
                // =============================================

                else if (
                    currentSortColumn ===
                    "alert_id"
                ) {

                    const result =
                        String(
                            valueA ?? ""
                        ).localeCompare(
                            String(
                                valueB ?? ""
                            ),
                            undefined,
                            {
                                numeric: true,
                                sensitivity: "base"
                            }
                        );


                    return currentSortDirection ===
                        "asc"
                        ? result
                        : -result;
                }


                // =============================================
                // NORMAL TEXT SORT
                // =============================================

                else {

                    valueA =
                        String(
                            valueA ?? ""
                        )
                            .toLowerCase();


                    valueB =
                        String(
                            valueB ?? ""
                        )
                            .toLowerCase();
                }


                // =============================================
                // FINAL COMPARISON
                // =============================================

                if (
                    valueA < valueB
                ) {

                    return currentSortDirection ===
                        "asc"
                        ? -1
                        : 1;
                }


                if (
                    valueA > valueB
                ) {

                    return currentSortDirection ===
                        "asc"
                        ? 1
                        : -1;
                }


                return 0;
            }
        );


    // =====================================================
    // RENDER ROWS
    // =====================================================

    sortedAlerts.forEach(
        alert => {

            const row =
                document.createElement(
                    "tr"
                );


            const severity =
                String(
                    alert.severity ?? ""
                )
                    .toLowerCase()
                    .trim();


            const status =
                String(
                    alert.status ?? ""
                )
                    .toLowerCase()
                    .trim()
                    .replace(
                        /\s+/g,
                        "-"
                    );


            row.innerHTML = `

                <td>

                    <button
                        class="alert-id-button"
                        onclick="openAlert('${escapeJs(alert.alert_id)}')"
                    >
                        ${escapeHtml(
                            alert.alert_id
                        )}
                    </button>

                </td>


                <td>

                    <span
                        class="severity-${escapeHtml(
                            severity
                        )}"
                    >
                        ${escapeHtml(
                            alert.severity || "-"
                        )}
                    </span>

                </td>


                <td>

                    ${escapeHtml(
                        alert.title || "-"
                    )}

                </td>


                <td>

                    ${escapeHtml(
                        alert.source_ip || "-"
                    )}

                </td>


                <td>

                    ${escapeHtml(
                        alert.threat_type || "-"
                    )}

                </td>


                <td>

                    <span
                        class="status-${escapeHtml(
                            status
                        )}"
                    >
                        ${escapeHtml(
                            alert.status || "-"
                        )}
                    </span>

                </td>

            `;


            table.appendChild(
                row
            );
        }
    );
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
                `/api/alerts/${encodeURIComponent(alertId)}`,
                {
                    method: "GET",
                    headers: {
                        "Accept":
                            "application/json"
                    },
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Request failed: ${response.status}`
            );
        }


        const data =
            await response.json();


        if (
            !data.success ||
            !data.alert
        ) {

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
 * SHOW ALERT DETAILS MODAL
 * =========================================================
 */

function showAlertDetails(alert) {

    let modal =
        document.getElementById(
            "alert-details-modal"
        );


    // =====================================================
    // CREATE MODAL IF IT DOES NOT EXIST
    // =====================================================

    if (!modal) {

        modal =
            document.createElement(
                "div"
            );


        modal.id =
            "alert-details-modal";


        modal.className =
            "alert-modal";


        document.body.appendChild(
            modal
        );
    }


    // =====================================================
    // NORMALIZE VALUES
    // =====================================================

    const severity =
        String(
            alert.severity ?? ""
        )
            .toLowerCase()
            .trim();


    const status =
        String(
            alert.status ?? ""
        )
            .toLowerCase()
            .trim()
            .replace(
                /\s+/g,
                "-"
            );


    // =====================================================
    // INVESTIGATION HISTORY
    // =====================================================

    const investigationHistory =
        Array.isArray(
            alert.investigation_history
        )
            ? alert.investigation_history
            : [];


    let historyHtml =
        `
            <p>
                No investigation history.
            </p>
        `;


    if (
        investigationHistory.length > 0
    ) {

        historyHtml =
            investigationHistory
                .map(
                    entry => {

                        return `

                            <div class="history-entry">

                                <strong>
                                    ${escapeHtml(
                                        entry.action ||
                                        "Action"
                                    )}
                                </strong>


                                <span>
                                    ${escapeHtml(
                                        entry.timestamp ||
                                        "-"
                                    )}
                                </span>


                                <p>
                                    ${escapeHtml(
                                        entry.details ||
                                        "-"
                                    )}
                                </p>

                            </div>

                        `;
                    }
                )
                .join("");
    }


    // =====================================================
    // MODAL HTML
    // =====================================================

    modal.innerHTML = `

        <div
            class="alert-modal-backdrop"
            onclick="closeAlertDetails()"
        ></div>


        <div class="alert-modal-content">


            <!-- =========================================
                 HEADER
            ========================================== -->

            <div class="alert-modal-header">

                <div>

                    <span class="modal-label">
                        SECURITY ALERT
                    </span>


                    <h2>
                        ${escapeHtml(
                            alert.alert_id ||
                            "-"
                        )}
                    </h2>


                    <p>
                        ${escapeHtml(
                            alert.title ||
                            "-"
                        )}
                    </p>

                </div>


                <button
                    class="modal-close"
                    onclick="closeAlertDetails()"
                    aria-label="Close"
                >
                    &times;
                </button>

            </div>


            <!-- =========================================
                 STATUS
            ========================================== -->

            <div class="alert-detail-status">

                <span>
                    Severity
                </span>


                <strong
                    class="severity-${escapeHtml(
                        severity
                    )}"
                >
                    ${escapeHtml(
                        alert.severity ||
                        "-"
                    )}
                </strong>


                <span>
                    Status
                </span>


                <strong
                    class="status-${escapeHtml(
                        status
                    )}"
                >
                    ${escapeHtml(
                        alert.status ||
                        "-"
                    )}
                </strong>

            </div>


            <!-- =========================================
                 ALERT INFORMATION
            ========================================== -->

            <div class="detail-section">

                <h3>
                    Alert Information
                </h3>


                <div class="detail-grid">


                    <div>

                        <span>
                            Alert ID
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.alert_id ||
                                "-"
                            )}
                        </strong>

                    </div>


                    <div>

                        <span>
                            Threat Type
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.threat_type ||
                                "-"
                            )}
                        </strong>

                    </div>


                    <div>

                        <span>
                            Source IP
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.source_ip ||
                                "-"
                            )}
                        </strong>

                    </div>


                    <div>

                        <span>
                            Timestamp
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.timestamp ||
                                "-"
                            )}
                        </strong>

                    </div>


                    <div>

                        <span>
                            Response Action
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.response_action ||
                                "-"
                            )}
                        </strong>

                    </div>


                    <div>

                        <span>
                            Response Status
                        </span>

                        <strong>
                            ${escapeHtml(
                                alert.response_status ||
                                "-"
                            )}
                        </strong>

                    </div>

                </div>

            </div>


            <!-- =========================================
                 DESCRIPTION
            ========================================== -->

            <div class="detail-section">

                <h3>
                    Description
                </h3>


                <p class="detail-description">
                    ${escapeHtml(
                        alert.description ||
                        "-"
                    )}
                </p>

            </div>


            <!-- =========================================
                 MITRE ATT&CK
            ========================================== -->

            <div class="detail-section">

                <h3>
                    MITRE ATT&CK
                </h3>


                <pre class="json-box">${escapeHtml(
                    formatJson(
                        alert.mitre_attack
                    )
                )}</pre>

            </div>


            <!-- =========================================
                 IOC ENRICHMENT
            ========================================== -->

            <div class="detail-section">

                <h3>
                    IOC Enrichment
                </h3>


                <pre class="json-box">${escapeHtml(
                    formatJson(
                        alert.ioc_enrichment
                    )
                )}</pre>

            </div>


            <!-- =========================================
                 INVESTIGATION HISTORY
            ========================================== -->

            <div class="detail-section">

                <h3>
                    Investigation History
                </h3>


                <div class="history-container">

                    ${historyHtml}

                </div>

            </div>


            <!-- =========================================
                 ANALYST NOTES
            ========================================== -->

            <div class="detail-section">

                <h3>
                    Analyst Notes
                </h3>


                <p class="detail-description">
                    ${escapeHtml(
                        alert.analyst_notes ||
                        "-"
                    )}
                </p>

            </div>


            <!-- =========================================
                 ACTIONS
            ========================================== -->

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


    // =====================================================
    // SHOW MODAL
    // =====================================================

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

async function investigateAlert(
    alertId
) {

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

async function containAlert(
    alertId
) {

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

async function collectEvidence(
    alertId
) {

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

async function executeResponse(
    alertId
) {

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

async function resolveAlert(
    alertId
) {

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

        console.log(
            "Executing action:",
            url
        );


        const response =
            await fetch(
                url,
                {
                    method: "POST",
                    headers: {
                        "Accept":
                            "application/json"
                    }
                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.message ||
                "Action failed"
            );
        }


        console.log(
            "Action successful:",
            successMessage
        );


        alert(
            successMessage
        );


        closeAlertDetails();


        // =====================================================
        // RELOAD DASHBOARD
        // =====================================================

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

function formatJson(
    value
) {

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

        return String(
            value
        );
    }
}


/*
 * =========================================================
 * HTML ESCAPE
 * =========================================================
 */

function escapeHtml(
    value
) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        value ?? "";


    return div.innerHTML;
}


/*
 * =========================================================
 * JAVASCRIPT STRING ESCAPE
 * =========================================================
 */

function escapeJs(
    value
) {

    return String(
        value ?? ""
    )
        .replace(
            /\\/g,
            "\\\\"
        )
        .replace(
            /'/g,
            "\\'"
        );
}


/*
 * =========================================================
 * SET TEXT HELPER
 * =========================================================
 */

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (element) {

        element.textContent =
            value;
    }
}


/*
 * =========================================================
 * REFRESH BUTTON
 * =========================================================
 */

function refreshDashboard() {

    loadDashboard();
}


/*
 * =========================================================
 * INITIALIZE DASHBOARD
 * =========================================================
 */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        console.log(
            "SOC Dashboard initialized"
        );


        // =============================================
        // LOAD INITIAL DATA
        // =============================================

        loadDashboard();


        // =============================================
        // SEARCH FILTER
        // =============================================

        const searchInput =
            document.getElementById(
                "alert-search"
            );


        if (searchInput) {

            searchInput.addEventListener(
                "input",
                filterAlerts
            );
        }


        // =============================================
        // SEVERITY FILTER
        // =============================================

        const severityFilter =
            document.getElementById(
                "severity-filter"
            );


        if (severityFilter) {

            severityFilter.addEventListener(
                "change",
                filterAlerts
            );
        }


        // =============================================
        // STATUS FILTER
        // =============================================

        const statusFilter =
            document.getElementById(
                "status-filter"
            );


        if (statusFilter) {

            statusFilter.addEventListener(
                "change",
                filterAlerts
            );
        }


        // =============================================
        // REFRESH BUTTON
        // =============================================

        const refreshButton =
            document.getElementById(
                "refresh-button"
            );


        if (refreshButton) {

            refreshButton.addEventListener(
                "click",
                refreshDashboard
            );
        }

    }
);