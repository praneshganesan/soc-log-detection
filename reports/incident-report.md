# SOC Incident Report

## Incident Summary

| Field | Details |
|---|---|
| Incident Type | Suspicious Authentication Activity |
| Alert Type | SUCCESS_AFTER_FAILURES |
| Severity | CRITICAL |
| Source IP | 192.168.1.55 |
| Target Username | pranesh |
| Failed Attempts | 6 |
| Successful Login | Yes |
| Detection Source | SSH Authentication Logs |
| Status | Requires Investigation |

## Executive Summary

The detection system identified a suspicious authentication sequence involving multiple failed login attempts followed by a successful authentication from the same source IP address.

Six failed authentication attempts were detected from `192.168.1.55` targeting the `pranesh` account. A successful login subsequently occurred from the same source.

The activity was classified as **CRITICAL** because successful authentication following repeated failures may indicate a successful credential attack or compromised credentials.

## Detection Details
```
Alert Type: SUCCESS_AFTER_FAILURES
Source IP: 192.168.1.55
Username: pranesh
Failed Attempts: 6
Severity: CRITICAL
```

## Analysis

The authentication sequence contains two important indicators:
1. Multiple failed authentication attempts.
2. A successful authentication after the failures.

This pattern can be associated with:
Brute-force attempts
Password guessing
Credential compromise
Unauthorized account access

The alert requires additional investigation to determine whether the successful authentication was legitimate.

## Investigation Steps

1. Identify the Source
Investigate the source IP address: 192.168.1.55

Determine whether it belongs to:
An authorized user
An internal workstation
A known server
An unknown or suspicious system

2. Review Authentication Timeline
Review authentication logs before and after the detected event.

Look for:
- Additional failed logins
- Additional successful logins
- Other targeted usernames
- Unusual login times
- Repeated authentication attempts

3. Validate the User
Confirm whether the user pranesh was expected to authenticate from the identified source IP.

4. Check for Additional Indicators
Look for:
- Multiple source IP addresses
- Privileged account targeting
- Username enumeration
- Unusual login locations
- Repeated authentication activity

## Risk Assessment

### Potential Impact
If the successful login was unauthorized, an attacker may have gained access to the affected account.

Potential consequences include:
- Unauthorized system access
- Account compromise
- Privilege escalation
- Data access
- Lateral movement

### Risk Level
CRITICAL

The combination of repeated failures followed by a successful authentication requires immediate investigation.

## Recommended Response
1. Validate whether the successful login was legitimate.
2. Review the affected account's recent activity.
3. Check the source system for suspicious activity.
4. Reset the account password if compromise is suspected.
5. Review privileged access associated with the account.
6. Investigate related authentication events.
7. Escalate the incident if unauthorized access is confirmed.

## Detection Logic
The alert was generated when the system identified a successful authentication following multiple failed authentication attempts from the same source IP.
Conceptually:
```
Multiple Failed Logins
        +
Successful Login
        |
        v
SUCCESS_AFTER_FAILURES
        |
        v
CRITICAL Alert
```

## MITRE ATT&CK Mapping
Potentially relevant techniques include:
T1110 — Brute Force
T1078 — Valid Accounts
The exact technique should be confirmed during investigation based on available evidence.

## Conclusion
The detection system successfully identified a suspicious authentication sequence involving repeated failed login attempts followed by a successful authentication.
The event was classified as CRITICAL and should be investigated to determine whether the successful login was legitimate or resulted from compromised credentials.

## Analyst Notes
This incident demonstrates the importance of correlating authentication events rather than investigating individual failed login attempts in isolation.
A successful authentication immediately following repeated failures can significantly increase the priority of an authentication-related alert.
