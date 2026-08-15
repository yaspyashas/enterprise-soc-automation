# =====================================================
# MITRE ATT&CK MAPPER
# =====================================================


MITRE_MAPPINGS = {

    "SSH Authentication Failure": {
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "tactic": "Initial Access",
        "reason": "Authentication activity was detected against an SSH service."
    },

    "SSH Brute Force": {
        "technique": "Password Guessing",
        "technique_id": "T1110",
        "tactic": "Credential Access",
        "reason": "Multiple failed SSH authentication attempts were detected from the same source IP."
    },

    "Successful SSH Authentication": {
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "tactic": "Initial Access",
        "reason": "A successful SSH authentication was detected."
    },

    "Privilege Escalation Activity": {
        "technique": "Abuse Elevation Control Mechanism",
        "technique_id": "T1548",
        "tactic": "Privilege Escalation",
        "reason": "A sudo command was executed with elevated privileges."
    },

    "Account Creation": {
        "technique": "Create Account",
        "technique_id": "T1136",
        "tactic": "Persistence",
        "reason": "A new user account creation event was detected."
    }
}


def map_alert_to_mitre(threat_type):
    """
    Map an alert threat type to MITRE ATT&CK information.
    """

    if not threat_type:
        return {
            "technique": "Not Available",
            "technique_id": "N/A",
            "tactic": "Not Available",
            "reason": "Threat type was not supplied."
        }

    return MITRE_MAPPINGS.get(
        threat_type,
        {
            "technique": "Not Available",
            "technique_id": "N/A",
            "tactic": "Not Available",
            "reason": "No MITRE ATT&CK mapping is configured for this threat type."
        }
    )