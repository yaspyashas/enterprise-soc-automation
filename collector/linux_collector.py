import os


class LinuxLogCollector:

    def __init__(self, log_file):
        self.log_file = log_file

    def collect(self):
        """
        Read authentication logs from the configured log file.
        """

        if not os.path.exists(self.log_file):
            raise FileNotFoundError(
                f"Log file not found: {self.log_file}"
            )

        with open(
            self.log_file,
            "r",
            encoding="utf-8"
        ) as file:

            logs = file.readlines()

        return [
            log.strip()
            for log in logs
            if log.strip()
        ]