
















from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect repeated failed login attempts from the same IP."""

    failed_ips = [
        event["source_ip"]
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts


def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)
from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect repeated failed login attempts from the same IP."""

    failed_ips = [
        event["source_ip"]
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts


def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)
from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect repeated failed login attempts from the same IP."""

    failed_ips = [
        event["source_ip"]
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts


def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)
from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect repeated failed login attempts from the same IP."""

    failed_ips = [
        event["source_ip"]
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts


def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)
from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect repeated failed login attempts from the same IP."""

    failed_ips = [
        event["source_ip"]
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    ip_counts = Counter(failed_ips)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "alert_type": "BRUTE_FORCE",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH"
            })

    return alerts


def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)
from collections import Counter, defaultdict
from log_parser import read_logs


FAILED_LOGIN_THRESHOLD = 5
INVALID_USER_THRESHOLD = 3
PRIVILEGED_ACCOUNT_THRESHOLD = 3

PRIVILEGED_ACCOUNTS = {
    "root",
    "administrator",
    "admin"
}


def detect_brute_force(events):
    """Detect 5 or more failed logins from the same IP within 5 minutes."""

    failed_by_ip = defaultdict(list)

    for event in events:
        if event["event_type"] == "FAILED_LOGIN":
            failed_by_ip[event["source_ip"]].append(event)

    alerts = []

    for ip, failed_events in failed_by_ip.items():

        failed_events.sort(key=lambda event: event["timestamp"])

        for i in range(len(failed_events)):

            window_start = failed_events[i]["timestamp"]

            window_events = [
                event
                for event in failed_events[i:]
                if (event["timestamp"] - window_start).total_seconds()
                <= 300
            ]

            if len(window_events) >= FAILED_LOGIN_THRESHOLD:

                alerts.append({
                    "alert_type": "BRUTE_FORCE",
                    "source_ip": ip,
                    "failed_attempts": len(window_events),
                    "window_minutes": 5,
                    "severity": "HIGH"
                })

                break

    return alerts

def detect_invalid_user_enumeration(events):
    """Detect multiple invalid usernames attempted from one IP."""

    usernames_by_ip = defaultdict(set)

    for event in events:
        if event["event_type"] == "INVALID_USER":
            usernames_by_ip[event["source_ip"]].add(
                event["username"]
            )

    alerts = []

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= INVALID_USER_THRESHOLD:
            alerts.append({
                "alert_type": "INVALID_USER_ENUMERATION",
                "source_ip": ip,
                "unique_usernames": len(usernames),
                "usernames": sorted(usernames),
                "severity": "MEDIUM"
            })

    return alerts


def detect_success_after_failures(events):
    """Detect successful logins that follow multiple failures."""

    failed_counts = defaultdict(int)
    alerts = []

    for event in events:
        ip = event["source_ip"]

        if event["event_type"] == "FAILED_LOGIN":
            failed_counts[ip] += 1

        elif event["event_type"] == "SUCCESSFUL_LOGIN":

            if failed_counts[ip] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "source_ip": ip,
                    "username": event["username"],
                    "failed_attempts": failed_counts[ip],
                    "severity": "CRITICAL"
                })

            failed_counts[ip] = 0

    return alerts


def detect_privileged_account_targeting(events):
    """Detect repeated failed logins targeting privileged accounts."""

    failed_targets = defaultdict(Counter)

    for event in events:
        if (
            event["event_type"] == "FAILED_LOGIN"
            and event["username"] in PRIVILEGED_ACCOUNTS
        ):
            failed_targets[event["source_ip"]][
                event["username"]
            ] += 1

    alerts = []

    for ip, usernames in failed_targets.items():
        for username, count in usernames.items():

            if count >= PRIVILEGED_ACCOUNT_THRESHOLD:
                alerts.append({
                    "alert_type": "PRIVILEGED_ACCOUNT_TARGETING",
                    "source_ip": ip,
                    "target_username": username,
                    "failed_attempts": count,
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":

    events = list(read_logs())

    brute_force_alerts = detect_brute_force(events)

    enumeration_alerts = detect_invalid_user_enumeration(events)

    success_after_failure_alerts = (
        detect_success_after_failures(events)
    )

    privileged_account_alerts = (
        detect_privileged_account_targeting(events)
    )

    print("\n=== BRUTE FORCE ALERTS ===")

    for alert in brute_force_alerts:
        print(alert)

    print("\n=== INVALID USER ENUMERATION ALERTS ===")

    for alert in enumeration_alerts:
        print(alert)

    print("\n=== SUCCESS AFTER FAILURES ALERTS ===")

    for alert in success_after_failure_alerts:
        print(alert)

    print("\n=== PRIVILEGED ACCOUNT TARGETING ALERTS ===")

    for alert in privileged_account_alerts:
        print(alert)

