import json
import os


PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


CONFIG_FILE = os.path.join(
    PROJECT_ROOT,
    "config",
    "config.json"
)


def load_config():
    """
    Load the main SOC automation configuration.
    """

    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            f"Configuration file not found: {CONFIG_FILE}"
        )

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def get_brute_force_threshold():
    """
    Return the configured SSH brute-force threshold.
    """

    config = load_config()

    return config["detection"]["brute_force_threshold"]


def is_threat_intelligence_enabled():
    """
    Return whether threat intelligence enrichment is enabled.
    """

    config = load_config()

    return config["threat_intelligence"]["enabled"]


def get_threat_intel_max_age_days():
    """
    Return the maximum age used for threat intelligence lookups.
    """

    config = load_config()

    return config["threat_intelligence"]["max_age_days"]

def get_threat_intel_api_key():
    """
    Return the AbuseIPDB API key from the environment.
    """

    return os.getenv("ABUSEIPDB_API_KEY")