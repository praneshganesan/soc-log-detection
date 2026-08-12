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
