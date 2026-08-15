from collections import defaultdict

from utils.config_loader import get_brute_force_threshold


class DetectionEngine:

    def __init__(self):
        self.brute_force_threshold = (
            get_brute_force_threshold()
        )

        self.failed_attempts = defaultdict(int)

    def detect(self, event):
        """
        Analyze one parsed event and return
        any security alerts generated from it.
        """

        alerts = []

        if not event:
            return alerts

        message = event.get(
            "message",
            ""
        )

        service = event.get(
            "service",
            ""
        )

        source_ip = event.get(
            "source_ip"
        )

        timestamp = event.get(
            "timestamp",
            ""
        )

        # -------------------------------------------------
        # Failed SSH Login
        # -------------------------------------------------

        if "Failed password" in message:

            alerts.append({
                "severity": "Medium",
                "title": "Failed SSH Login",
                "description": message,
                "source_ip": source_ip,
                "threat_type": "SSH Authentication Failure",
                "timestamp": timestamp
            })

            # ---------------------------------------------
            # Track failed attempts
            # ---------------------------------------------

            if source_ip:

                self.failed_attempts[source_ip] += 1

                attempts = self.failed_attempts[
                    source_ip
                ]

                # -----------------------------------------
                # SSH Brute Force
                # -----------------------------------------

                if attempts >= self.brute_force_threshold:

                    alerts.append({
                        "severity": "High",
                        "title": "SSH Brute Force Attack",
                        "description": (
                            f"{attempts} failed SSH login "
                            f"attempts detected from "
                            f"{source_ip}"
                        ),
                        "source_ip": source_ip,
                        "threat_type": "SSH Brute Force",
                        "timestamp": timestamp,
                        "attempt_count": attempts
                    })

        # -------------------------------------------------
        # Successful SSH Login
        # -------------------------------------------------

        if "Accepted password" in message:

            alerts.append({
                "severity": "Low",
                "title": "Successful SSH Login",
                "description": message,
                "source_ip": source_ip,
                "threat_type": "Successful SSH Authentication",
                "timestamp": timestamp
            })

        # -------------------------------------------------
        # Sudo Command
        # -------------------------------------------------

        if service == "sudo":

            alerts.append({
                "severity": "Medium",
                "title": "Sudo Command Executed",
                "description": message,
                "source_ip": source_ip,
                "threat_type": "Privilege Escalation Activity",
                "timestamp": timestamp
            })

        # -------------------------------------------------
        # New User
        # -------------------------------------------------

        if service == "useradd":

            alerts.append({
                "severity": "High",
                "title": "New User Created",
                "description": message,
                "source_ip": source_ip,
                "threat_type": "Account Creation",
                "timestamp": timestamp
            })

        return alerts