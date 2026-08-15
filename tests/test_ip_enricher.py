from threat_intelligence.ip_enricher import enrich_ip


def test_enrich_private_ip():

    result = enrich_ip("192.168.1.20")

    assert isinstance(result, dict)

    assert result["ip"] == "192.168.1.20"

    assert result["type"] == "Private IPv4"

    assert result["reputation"] == "Internal"


def test_enrich_invalid_ip():

    result = enrich_ip("192.168.1.999")

    assert isinstance(result, dict)

    assert result["ip"] == "192.168.1.999"

    assert result["type"] == "Invalid"


def test_enrich_none_ip():

    result = enrich_ip(None)

    assert isinstance(result, dict)

    assert result["ip"] == "Unknown"

    assert result["type"] == "Unknown"

def test_enrich_public_ip():

    result = enrich_ip("8.8.8.8")

    assert isinstance(result, dict)

    assert result["ip"] == "8.8.8.8"

    assert result["type"] == "Public IPv4"