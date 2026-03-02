# HA Wazuh Agent Add-on

Home Assistant add-on that runs a **Wazuh Agent** inside HA OS and forwards logs/events to your **Wazuh Manager**.

Primary goal: **as native as possible** for any HA install — no HA-side custom integrations required.  
It focuses on:

- enrolling an agent (`agent-auth`)
- forwarding HA logs (prefer `journald`, optionally `/config/home-assistant.log`)
- keeping the container footprint sane (minimal profile by default)

---

## What you get

- ✅ Wazuh Agent enrolled to your manager
- ✅ Log forwarding from Home Assistant host via:
  - `journald` (default)
  - `/config/home-assistant.log` (if present)
- ✅ Persistent enrollment keys stored under add-on storage (`/data/ossec/etc/client.keys`)
- ✅ Optional “minimal” security profile:
  - disables container-noisy modules (`syscheck`, `rootcheck`, `syscollector`)
  - disables `agent-upgrade`
  - removes command-based collectors (`df`, `netstat`, `last`)
  - keeps only HA log sources (no `dpkg.log` / `active-responses` noise)

---

## Install

1. Add this repository to Home Assistant  
   Settings → Add-ons → Add-on Store → ⋮ → Repositories  
   Add:

   ```
   https://github.com/BeardedTinker/ha-wazuh-agent-addon
   ```

2. Install **Wazuh Agent** add-on  
3. Configure options (see below)  
4. Start the add-on  

---

## Configuration options

### Required

- `manager_address`  
  Wazuh Manager IP/hostname (example: `192.168.1.39`)

- `agent_name`  
  Name shown in Wazuh (example: `home-assistant`)

- `enrollment_key`  
  Authentication password from your manager (`authd.pass`), used by `agent-auth`

---

### Optional

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

  - `minimal` → Best for HA add-on usage (less noise, less host scanning)
  - `standard` → Keeps Wazuh defaults, still prevents auto-enrollment loop

- `debug_dump_config` (default: `false`)  
  Prints helpful debug info (`ossec.conf` head, directory listings).  
  Do not keep enabled long-term.

---

## Example configuration

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

---

## Troubleshooting

### Duplicate agent name

If you see:

```
Duplicate agent name: home-assistant
```

The agent already exists on the Wazuh Manager.

**Fix options:**

- Delete the existing agent in the Wazuh Manager UI and restart the add-on.
- Or change `agent_name` in the add-on configuration and restart.

---

### Enrollment succeeded but keys are missing

This add-on persists enrollment keys to:

```
/data/ossec/etc/client.keys
```

If persistence is not working:

1. Temporarily set `debug_dump_config: true`
2. Restart the add-on
3. Check logs for `/data/ossec/etc` directory listing
4. Verify that `client.keys` is not empty

Disable debug mode after verification.

---

### Agent keeps trying to enroll again (invalid password)

This add-on removes the `<enrollment>` block from `ossec.conf` to prevent `wazuh-agentd` auto-enrollment loops.

If you manually added `<enrollment>` sections, remove them.

Also verify:

- `enrollment_key` matches the value in your manager's `authd.pass`
- The agent was deleted from the manager before re-enrolling

---

## Security notes

This add-on requires read-only access to:

- Journald
- Home Assistant log directories

The default `minimal` security profile:

- Disables host-level scanning modules inside the HA container
- Prevents command-based collectors
- Reduces noise in Wazuh
- Keeps SCA (Security Configuration Assessment) enabled as a lightweight baseline security check

If full host-level inspection is required, switch to `standard` profile.

---

## Network requirements

The add-on must reach your Wazuh Manager:

- TCP 1515 — Enrollment (`agent-auth`)
- TCP 1514 — Agent communication

Ensure firewall rules allow these connections.

---

## Version

Current version: **0.3.0**

Highlights:

- Hardened enrollment logic
- Stable key persistence
- Auto-enrollment loop prevention
- Minimal security profile
- No runtime package installs
- Clean restart behavior
- Production-ready configuration validation

## License & Upstream Notice

This project (HA Wazuh Agent Add-on) is licensed under the MIT License.

It installs and runs the official Wazuh Agent package provided by Wazuh, Inc.

Wazuh itself is licensed under the GNU General Public License v2 (GPLv2).
This add-on does not modify, redistribute, or bundle Wazuh source code.
It only installs the official Wazuh agent package inside a Home Assistant add-on container.

All trademarks and copyrights related to Wazuh belong to their respective owners.

For full Wazuh licensing details, see:
https://github.com/wazuh/wazuh/blob/main/LICENSE
