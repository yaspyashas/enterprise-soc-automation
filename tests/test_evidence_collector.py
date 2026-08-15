import pytest

from evidence.evidence_collector import collect_evidence


@pytest.fixture
def test_alert():

    return {
        "alert_id": "ALT-TEST-0001",
        "severity": "High",
        "title": "SSH Brute Force Attack",
        "description": (
            "3 failed SSH login attempts detected "
            "from 192.168.1.20"
        ),
        "source_ip": "192.168.1.20",
        "threat_type": "SSH Brute Force",
        "timestamp": "Aug 12 10:15:09",
        "status": "Open",

        "mitre_attack": {
            "technique": "Password Guessing",
            "technique_id": "T1110",
            "tactic": "Credential Access",
            "reason": (
                "Multiple failed SSH authentication attempts "
                "were detected from the same source IP."
            )
        },

        "ioc_enrichment": {
            "ip": "192.168.1.20",
            "type": "Private IPv4",
            "reputation": "Internal",
            "country": "Internal Network",
            "threat_level": "N/A",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Internal Network"
        },

        "investigation_history": [
            {
                "action": "Alert Created",
                "timestamp": "2026-08-13 00:00:40",
                "details": "SSH Brute Force Attack"
            }
        ]
    }


def test_collect_evidence_returns_result(test_alert):

    result = collect_evidence(test_alert)

    assert result is not None

    assert isinstance(result, dict)


def test_collect_evidence_success(test_alert):

    result = collect_evidence(test_alert)

    assert result.get("success") is True


def test_collect_evidence_creates_evidence_file(test_alert):

    result = collect_evidence(test_alert)

    assert result.get("evidence_file") == (
        "ALT-TEST-0001_evidence.json"
    )

    assert result.get("evidence_path")

    assert result["evidence_path"].endswith(
        "ALT-TEST-0001_evidence.json"
    )