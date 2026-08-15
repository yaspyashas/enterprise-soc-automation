import re


class LogParser:

    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[^\s\[]+)"
        r"(?:\[\d+\])?:\s+"
        r"(?P<message>.*)$"
    )

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    def parse_log(self, log_line):
        """
        Convert a raw authentication log line
        into a structured dictionary.
        """

        if not log_line:
            return None

        match = self.LOG_PATTERN.match(
            log_line.strip()
        )

        if not match:
            return None

        data = match.groupdict()

        ip_match = self.IP_PATTERN.search(
            data["message"]
        )

        if ip_match:
            data["source_ip"] = ip_match.group()
        else:
            data["source_ip"] = None

        return data