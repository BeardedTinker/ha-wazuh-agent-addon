# Architecture

This add-on positions Home Assistant as a monitored endpoint
inside a centralized security architecture.

## Design Goals

- No HA core modification
- No privileged host access
- Outbound-only communication
- Deterministic startup behavior

## Why Wazuh?

Wazuh provides:
- Parsing
- Detection
- Correlation
- Historical visibility

Syslog moves logs.
Wazuh interprets them.
