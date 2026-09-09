![GitHub Release](https://img.shields.io/github/v/release/BeardedTinker/ha-wazuh-agent-addon)
![License](https://img.shields.io/github/license/BeardedTinker/ha-wazuh-agent-addon)
![Build](https://img.shields.io/github/actions/workflow/status/BeardedTinker/ha-wazuh-agent-addon/build-addon.yml)

# HA Wazuh Agent Add-on

Security logging and host visibility for **Home Assistant OS** using **Wazuh**.

> This add-on runs an official **Wazuh Agent** inside Home Assistant and forwards HA host logs/events to your **Wazuh Manager**.  
> Primary goal: **as native as possible** for any HA install — **no HA-side custom integrations required**.

---

## Table of contents

- [What is Wazuh?](#what-is-wazuh)
- [Why would you want this in Home Assistant?](#why-would-you-want-this-in-home-assistant)
- [Architectural motivation](#architectural-motivation)
- [What this add-on does](#what-this-add-on-does)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Security profiles](#security-profiles)
- [Install](#install)
- [Configuration options](#configuration-options)
- [Example config](#example-config)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## What is Wazuh?

Wazuh is an open-source security monitoring platform that provides:

- Log analysis
- File Integrity Monitoring (FIM)
- Security Configuration Assessment (SCA)
- Intrusion detection
- Threat detection & alerting
- Centralized event correlation

In simple terms:

> Wazuh turns raw logs into structured, searchable, security-relevant events.

Wazuh is widely used as a SIEM/HIDS building block in enterprise environments.

Project: https://github.com/wazuh/wazuh

---

## Why would you want this in Home Assistant?

Home Assistant produces logs — but **logs ≠ security telemetry**.

Today, Home Assistant does not provide a standardized native pipeline for:
- structured security events
- centralized threat visibility
- compliance-style baseline checks
- long-term security correlation across infrastructure

This add-on enables Home Assistant to act like a monitored system within a broader security architecture (homelab or prosumer/enterprise-like setups).

---

## Architectural motivation

This add-on is directly related to the architectural discussion:

👉 https://github.com/home-assistant/architecture/discussions/1346

That proposal explores improving structured security logging inside HA core.

Until HA has standardized security telemetry, this add-on provides a **production-ready “do it today”** solution:
- immediate structured log forwarding
- security event classification in Wazuh
- optional baseline security assessment (SCA)
- centralized monitoring and retention

This is not meant to replace future HA-native security logging — it complements it.

---

## What this add-on does

This add-on:

- installs the official Wazuh Agent
- enrolls it to your Wazuh Manager (`agent-auth`, with or without password)
- forwards HA logs (prefer `journald`, optionally `/config/home-assistant.log`)
- persists agent keys in add-on storage (`/data/ossec/etc/client.keys`)
- prevents auto-enrollment loops (removes `<enrollment>` block from `ossec.conf`)
- offers a low-noise **minimal** profile tuned for HA OS

It does **not**:

- modify Wazuh source code
- replace Home Assistant logging
- act as a Wazuh Manager
- open inbound ports (outbound-only to the manager)

---

## Screenshots

Wazuh dashboard view (example):

<img width="1597" height="898" alt="Wazuh dashboard example" src="https://github.com/user-attachments/assets/fbb9f901-ae09-4563-8b36-2a25d44387f5" />

---

## Architecture

```text
Home Assistant OS
        |
        |  (journald / HA logs)
        v
HA Wazuh Agent (Add-on container)
        |
        |  TCP 1514 (agent -> manager)
        v
Wazuh Manager
        |
        v
Wazuh Indexer / Dashboard
```

### Data flow

1. Home Assistant generates system and application logs.
2. The Wazuh Agent collects logs via:
   - `journald` (default)
   - `/config/home-assistant.log` (if present)
3. Events are parsed/normalized and sent to the Wazuh Manager.
4. The manager correlates events and forwards them to the dashboard/indexer.
5. Alerts, SCA scores, and anomalies become centrally visible.

---

## Security model

This add-on is designed to respect the Home Assistant OS “appliance” model.

### Access and permissions

- runs inside an isolated add-on container
- **read-only** access to journald is used for log collection
- optional read-only access to `/config/home-assistant.log`
- no privileged host control is required

### Network

- outbound connection to your Wazuh Manager only
- uses standard Wazuh ports:
  - `1515/tcp` enrollment (`agent-auth`)
  - `1514/tcp` event forwarding

---

## Security profiles

### Minimal (default)

Recommended for most HA installations.

- disables container-noisy modules:
  - `syscheck` (FIM)
  - `rootcheck`
  - `syscollector`
- disables:
  - `agent-upgrade`
  - command collectors (`df`, `netstat`, `last`)
- keeps:
  - HA log forwarding
  - SCA (lightweight baseline check)

Why? HA OS is an appliance-style system. Full host scanning from an add-on container can create noise without meaningful value.

### Standard

For advanced users who want more of the Wazuh defaults.

- keeps Wazuh defaults as much as possible
- still prevents auto-enrollment loops

Use this only if you understand the implications of scanning inside the HA environment.

---

## Install

1) Add this repository to Home Assistant:

- Settings → Add-ons (Apps) → Add-on Store → ⋮ → Repositories  
- Add:

`https://github.com/BeardedTinker/ha-wazuh-agent-addon`

2) Install **Wazuh Agent**  
3) Configure options (see below)  
4) Start the add-on

---

## Configuration options

### Required

- `manager_address`  
  Wazuh Manager IP/hostname (example: `192.168.1.39`)

- `agent_name`  
  Name shown in Wazuh (example: `home-assistant`)

### Optional

- `enrollment_key`  
  Authentication password from your manager (`authd.pass`), used by `agent-auth` only when this field is not empty.
  Leave it empty if your Wazuh Manager allows passwordless enrollment.

- `agent_group`  
  Assign agent to a manager group during enrollment

- `enrollment_port` (default: `1515`)  
  Manager authd port

- `communication_port` (default: `1514`)  
  Manager agent communication port

- `force_reenroll` (default: `false`)  
  If `true`, wipes persisted `client.keys` and forces new enrollment on next start.
  Useful after deleting/recreating agent on manager.

- `security_profile` (default: `minimal`)  
  - `minimal`: best for HA add-on usage (less noise, less host scanning)
  - `standard`: keep Wazuh defaults, still prevents auto-enrollment loop

- `debug_dump_config` (default: `false`)  
  Prints helpful debug info (ossec.conf head, dir listings). Do not keep enabled long-term.

### Enrollment with password vs without password

The add-on behavior is determined directly by the startup script:

- if `enrollment_key` is not empty, the add-on runs `agent-auth` with `-P <password>`
- if `enrollment_key` is empty, the add-on does **not** pass `-P`, so enrollment is attempted without a password

That means:

- for passwordless enrollment, you do **not** need to first set a password and then remove it
- just leave `enrollment_key` empty from the start
- this only works if your Wazuh Manager is configured to accept enrollment without `authd.pass`

If you already enrolled the agent once, changing `enrollment_key` alone may appear to do nothing. That is expected: the add-on reuses persisted keys from `/data/ossec/etc/client.keys` and only enrolls again when those keys are missing or you force a new enrollment.

### Passwordless enrollment checklist

1. Configure your Wazuh Manager to allow agent enrollment without a password.
2. In the add-on configuration, set `manager_address` and `agent_name`.
3. Leave `enrollment_key` empty.
4. Start the add-on.

If the agent had already been enrolled before:

1. Delete the existing agent entry in Wazuh Manager if needed.
2. Set `force_reenroll: true`.
3. Keep `enrollment_key` empty.
4. Restart the add-on once.
5. After successful enrollment, set `force_reenroll: false` again.

---

## Example config

### With password

```yaml
manager_address: "192.168.1.39"
agent_name: "home-assistant"
agent_group: ""
enrollment_port: 1515
communication_port: 1514
enrollment_key: "YOUR_AUTHD_PASS"
force_reenroll: false
security_profile: "minimal"
debug_dump_config: false
```

### Without password

```yaml
manager_address: "192.168.1.39"
agent_name: "home-assistant"
agent_group: ""
enrollment_port: 1515
communication_port: 1514
enrollment_key: ""
force_reenroll: false
security_profile: "minimal"
debug_dump_config: false
```

---

## Troubleshooting

### Duplicate agent name

If you see:

`Duplicate agent name: home-assistant`

Fix options:

1) Delete the existing agent in Wazuh Manager UI and restart the add-on  
2) Or change `agent_name` in the add-on configuration

### Enrollment succeeded but keys are missing

This add-on persists keys to:

`/data/ossec/etc/client.keys`

If persistence is not working:

1) Set `debug_dump_config: true` (one run only)  
2) Restart the add-on  
3) Check logs for `/data/ossec/etc` directory listing and permissions

### Agent keeps trying to enroll again (invalid password)

This add-on removes `<enrollment>` from `ossec.conf` to prevent `wazuh-agentd` auto-enrollment.

If you manually added enrollment blocks, remove them.

If you want passwordless enrollment, make sure `enrollment_key` is empty. If the add-on was previously enrolled with other credentials, temporarily set `force_reenroll: true` and restart once.

### Security notes

- This add-on needs read-only access to journald and HA folders to collect logs.
- Default `minimal` profile intentionally reduces scanning/command execution inside HA environment.
- SCA (Security Configuration Assessment) can be enabled/disabled by Wazuh config; `minimal` keeps it available as a lightweight “security check”.

---

## Limitations

- This is not a Wazuh Manager.
- It does not magically secure Home Assistant.
- It depends on proper Wazuh Manager configuration.

---

## Roadmap

- Improve docs and diagrams
- Optional dashboards / Wazuh rules for HA-specific patterns
- Align with future HA security logging pipeline work (see architectural discussion)

---

## License

MIT. See [LICENSE](LICENSE).

---

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md).
