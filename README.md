# SOC Log Detection & Alerting System

A Python-based security monitoring project that analyzes SSH authentication logs and detects suspicious authentication activity.

## Project Overview

This project simulates a basic Security Operations Center (SOC) detection workflow.

The system processes authentication logs, identifies suspicious patterns, and generates security alerts based on predefined detection rules.

## Detection Capabilities

The system currently detects:

- Brute-force authentication attempts
- Invalid username enumeration
- Successful login after repeated failures
- Privileged account targeting
- Time-based authentication patterns

## Architecture

```text
Authentication Logs
        |
        v
   Log Parser
        |
        v
 Structured Events
        |
        v
 Detection Engine
        |
        v
 Security Alerts
```

## Technologies Used

- Python 3
- Linux
- Ubuntu
- Windows Subsystem for Linux (WSL)
- Git
- GitHub
- Regular Expressions
- SSH Authentication Logs
- SOC Detection Concepts

## Project Structure

```text
soc-log-detection/
|
├── data/
│   └── auth.log
|
├── src/
│   ├── log_parser.py
│   └── detection_engine.py
|
├── .gitignore
└── README.md
```

## Detection Rules

### 1. Brute Force Detection
Detects repeated failed authentication attempts from the same source IP.

Example:
Source IP: 192.168.1.55  
Failed Attempts: 6  
Severity: HIGH

### 2. Invalid User Enumeration
Detects multiple invalid usernames attempted from a single source IP.

Example:
Source IP: 10.10.10.25
Usernames:
- admin
- administrator
- guest
- oracle
- postgres
- test
Unique Usernames: 6  
Severity: MEDIUM

### 3. Successful Login After Failures
Detects a successful authentication event following multiple failed login attempts.

Example:
Source IP: 192.168.1.55  
Username: pranesh  
Failed Attempts: 6  
Severity: CRITICAL

This detection identifies a suspicious authentication sequence that may require further investigation.

### 4. Privileged Account Targeting
Detects repeated failed authentication attempts targeting privileged accounts such as root, administrator, or admin.

Example:
Source IP: 172.16.20.44  
Target Username: root  
Failed Attempts: 5  
Severity: HIGH

## Sample Detection Output

### Brute Force
```
=== BRUTE FORCE ALERTS ===

{'alert_type': 'BRUTE_FORCE',
 'source_ip': '192.168.1.55',
 'failed_attempts': 6,
 'severity': 'HIGH'}

{'alert_type': 'BRUTE_FORCE',
 'source_ip': '172.16.20.44',
 'failed_attempts': 5,
 'severity': 'HIGH'}

### Invalid User Enumeration

=== INVALID USER ENUMERATION ALERTS ===

{'alert_type': 'INVALID_USER_ENUMERATION',
 'source_ip': '10.10.10.25',
 'unique_usernames': 6,
 'usernames': ['admin', 'administrator', 'guest',
               'oracle', 'postgres', 'test'],
 'severity': 'MEDIUM'}

### Successful Login After Failures

=== SUCCESS AFTER FAILURES ALERTS ===

{'alert_type': 'SUCCESS_AFTER_FAILURES',
 'source_ip': '192.168.1.55',
 'username': 'pranesh',
 'failed_attempts': 6,
 'severity': 'CRITICAL'}

### Privileged Account Targeting

=== PRIVILEGED ACCOUNT TARGETING ALERTS ===

{'alert_type': 'PRIVILEGED_ACCOUNT_TARGETING',
 'source_ip': '172.16.20.44',
 'target_username': 'root',
 'failed_attempts': 5,
 'severity': 'HIGH'}
```

## Security Concepts Demonstrated

- Authentication monitoring
- Linux log analysis
- SSH security monitoring
- Detection engineering
- Brute-force detection
- Account enumeration
- Privileged account monitoring
- Suspicious authentication analysis
- Security alert generation
- Basic SOC investigation
- Git version control
- GitHub project management

## Learning Outcomes
Through this project, I practiced:

- Working with the Linux command line
- Parsing authentication logs using Python
- Using regular expressions to extract security events
- Creating security detection rules
- Analyzing authentication behavior
- Understanding SOC alerting workflows
- Investigating suspicious authentication activity
- Using Git for version control
- Managing a cybersecurity project with GitHub

## Example Investigation

A suspicious authentication sequence can be investigated using the generated alert information.

Example:
Source IP: 192.168.1.55
Activity: 6 failed authentication attempts followed by a successful login
Username: pranesh
Severity: CRITICAL

Possible SOC investigation steps:

1. Identify the source IP.
2. Review the authentication timeline.
3. Determine which account was targeted.
4. Check whether the source IP is known or trusted.
5. Review additional authentication activity.
6. Determine whether the successful login was legitimate.
7. Escalate the incident if compromise is suspected.


## Security Analyst Workflow
```
Authentication Logs
        |
        v
Log Collection
        |
        v
Event Parsing
        |
        v
Detection Rules
        |
        v
Alert Generation
        |
        v
Investigation
        |
        v
Incident Assessment
        |
        v
Response / Escalation
```

## Future Improvements

- Web-based SOC dashboard
- Automated incident report generation
- Real-time log monitoring
- Email or messaging alerts
- MITRE ATT&CK technique mapping
- Unit testing
- Improved time-window detection
- Configurable detection thresholds
- Alert deduplication
- Risk and confidence scoring
- Detection rule configuration
- JSON/CSV alert export

## Disclaimer

This project uses synthetic authentication logs for educational and defensive cybersecurity research purposes.

No unauthorized systems or real-world targets were used.


## Author

**Pranesh Ganesan**

Computer Science Engineering | Cybersecurity

GitHub: https://github.com/praneshganesan
