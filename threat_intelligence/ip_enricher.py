import ipaddress
import requests

from utils.config_loader import (
    get_threat_intel_api_key,
    get_threat_intel_max_age_days
)


def enrich_ip(source_ip):
    """
    Validate, classify, and enrich an IP address
    using AbuseIPDB for public IPv4 addresses.
    """

    # =====================================================
    # No IP supplied
    # =====================================================

    if not source_ip:
        return {
            "ip": "Unknown",
            "type": "Unknown",
            "reputation": "Unknown",
            "country": "Unknown",
            "threat_level": "Unknown",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Unknown"
        }

    # =====================================================
    # Validate IP address
    # =====================================================

    try:
        ip = ipaddress.ip_address(source_ip)

    except ValueError:
        return {
            "ip": source_ip,
            "type": "Invalid",
            "reputation": "Invalid",
            "country": "Unknown",
            "threat_level": "Unknown",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Unknown"
        }

    # =====================================================
    # Private / Internal IP
    # =====================================================

    if ip.is_private:
        return {
            "ip": source_ip,
            "type": "Private IPv4",
            "reputation": "Internal",
            "country": "Internal Network",
            "threat_level": "N/A",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Internal Network"
        }

    # =====================================================
    # IPv6
    # =====================================================

    if ip.version != 4:
        return {
            "ip": source_ip,
            "type": "IPv6",
            "reputation": "Unsupported",
            "country": "Unknown",
            "threat_level": "Unknown",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Unknown"
        }

    # =====================================================
    # Get AbuseIPDB API key
    # =====================================================

    api_key = get_threat_intel_api_key()

    if not api_key:
        return {
            "ip": source_ip,
            "type": "Public IPv4",
            "reputation": "Unavailable",
            "country": "Unknown",
            "threat_level": "Unknown",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Unknown"
        }

    # =====================================================
    # Get configured lookup age
    # =====================================================

    max_age_days = get_threat_intel_max_age_days()

    # =====================================================
    # AbuseIPDB API
    # =====================================================

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": source_ip,
        "maxAgeInDays": max_age_days
    }

    # =====================================================
    # API request
    # =====================================================

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        result = response.json()

        data = result.get(
            "data",
            {}
        )

        # =================================================
        # Abuse confidence
        # =================================================

        abuse_confidence = data.get(
            "abuseConfidenceScore",
            0
        )

        # =================================================
        # Threat level
        # =================================================

        if abuse_confidence >= 75:
            threat_level = "High"

        elif abuse_confidence >= 25:
            threat_level = "Medium"

        else:
            threat_level = "Low"

        # =================================================
        # Reputation
        # =================================================

        if abuse_confidence >= 75:
            reputation = "Malicious"

        elif abuse_confidence >= 25:
            reputation = "Suspicious"

        else:
            reputation = "Clean"

        # =================================================
        # Return enrichment
        # =================================================

        return {
            "ip": source_ip,
            "type": "Public IPv4",
            "reputation": reputation,
            "country": data.get(
                "countryCode",
                "Unknown"
            ),
            "threat_level": threat_level,
            "abuse_confidence": abuse_confidence,
            "total_reports": data.get(
                "totalReports",
                0
            ),
            "isp": data.get(
                "isp",
                "Unknown"
            )
        }

    except requests.RequestException as error:

        print(
            f"AbuseIPDB API error: {error}"
        )

        return {
            "ip": source_ip,
            "type": "Public IPv4",
            "reputation": "Unavailable",
            "country": "Unknown",
            "threat_level": "Unknown",
            "abuse_confidence": 0,
            "total_reports": 0,
            "isp": "Unknown"
        }