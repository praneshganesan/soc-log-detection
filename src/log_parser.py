import re
from datetime import datetime
from pathlib import Path


LOG_FILE = Path("data/auth.log")

CURRENT_YEAR = 2026


def parse_timestamp(line):
    """Extract timestamp from a log line."""

    match = re.match(
        r"^([A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2})",
        line
    )

    if not match:
        return None

    timestamp_string = match.group(1)

    return datetime.strptime(
        f"{CURRENT_YEAR} {timestamp_string}",
        "%Y %b %d %H:%M:%S"
    )


def parse_log_line(line):
    """Parse a single SSH authentication log line."""

    line = line.strip()

    timestamp = parse_timestamp(line)

    # Failed login
    match = re.search(
        r"Failed password for (\S+) from ([\d.]+)",
        line
    )

    if match:
        return {
            "timestamp": timestamp,
            "event_type": "FAILED_LOGIN",
            "username": match.group(1),
            "source_ip": match.group(2),
            "raw_log": line
        }

    # Successful login
    match = re.search(
        r"Accepted password for (\S+) from ([\d.]+)",
        line
    )

    if match:
        return {
            "timestamp": timestamp,
            "event_type": "SUCCESSFUL_LOGIN",
            "username": match.group(1),
            "source_ip": match.group(2),
            "raw_log": line
        }

    # Invalid username
    match = re.search(
        r"Invalid user (\S+) from ([\d.]+)",
        line
    )

    if match:
        return {
            "timestamp": timestamp,
            "event_type": "INVALID_USER",
            "username": match.group(1),
            "source_ip": match.group(2),
            "raw_log": line
        }

    return {
        "timestamp": timestamp,
        "event_type": "UNKNOWN",
        "username": None,
        "source_ip": None,
        "raw_log": line
    }


def read_logs():
    """Read and parse authentication logs."""

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                yield parse_log_line(line)


if __name__ == "__main__":
    for event in read_logs():
        print(event)
