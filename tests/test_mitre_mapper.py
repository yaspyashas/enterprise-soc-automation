from mitre.mitre_mapper import map_alert_to_mitre


def test_map_ssh_brute_force():

    result = map_alert_to_mitre(
        "SSH Brute Force"
    )

    assert isinstance(result, dict)

    assert result["technique"] == "Password Guessing"
    assert result["technique_id"] == "T1110"
    assert result["tactic"] == "Credential Access"


def test_map_account_creation():

    result = map_alert_to_mitre(
        "Account Creation"
    )

    assert isinstance(result, dict)

    assert result["technique"]
    assert result["technique_id"]
    assert result["tactic"]


def test_map_unknown_threat():

    result = map_alert_to_mitre(
        "Unknown Threat"
    )

    assert isinstance(result, dict)

    assert "technique" in result
    assert "technique_id" in result
    assert "tactic" in result
    assert "reason" in result


def test_map_none_threat():

    result = map_alert_to_mitre(
        None
    )

    assert isinstance(result, dict)

    assert "technique" in result
    assert "technique_id" in result
    assert "tactic" in result