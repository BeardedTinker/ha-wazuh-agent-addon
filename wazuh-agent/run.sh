#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
LOGFILE="/config/home-assistant.log"
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key' "$OPTS")"

echo "[wazuh-agent] manager_address=$MANAGER_ADDRESS"
echo "[wazuh-agent] agent_name=$AGENT_NAME"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"

if [ -z "$MANAGER_ADDRESS" ] || [ "$MANAGER_ADDRESS" = "null" ]; then
  echo "[wazuh-agent] ERROR: manager_address missing"
  exit 1
fi

if [ -z "$AGENT_NAME" ] || [ "$AGENT_NAME" = "null" ]; then
  echo "[wazuh-agent] ERROR: agent_name missing"
  exit 1
fi

if [ -z "$ENROLLMENT_KEY" ] || [ "$ENROLLMENT_KEY" = "null" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key missing"
  exit 1
fi

# -------------------------------------------------
# Ensure manager address
# -------------------------------------------------
if [ -f "$CONF" ]; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
fi

# -------------------------------------------------
# Disable host-specific modules (container != host)
# -------------------------------------------------
for tag in syscheck rootcheck; do
  if grep -q "<${tag}>" "$CONF"; then
    sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF" || true
  fi
done

# -------------------------------------------------
# Add HA log source
# -------------------------------------------------
if [ -f "$LOGFILE" ]; then
  echo "[wazuh-agent] Using HA file log"
  if ! grep -q "$LOGFILE" "$CONF"; then
    awk -v lf="$LOGFILE" '
      /<\/ossec_config>/ && !done {
        print "  <localfile>";
        print "    <log_format>syslog</log_format>";
        print "    <location>" lf "</location>";
        print "  </localfile>";
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
else
  echo "[wazuh-agent] No HA log file found, using journald"

  if ! grep -q "CONTAINER_NAME=homeassistant" "$CONF"; then
    awk '
      /<\/ossec_config>/ && !done {
        print "  <localfile>";
        print "    <log_format>command</log_format>";
        print "    <command>journalctl -f -o short-iso CONTAINER_NAME=homeassistant --no-pager</command>";
        print "  </localfile>";
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
fi

# -------------------------------------------------
# Persist client.keys
# -------------------------------------------------
mkdir -p "$PERSIST_DIR"

if [ -f /var/ossec/etc/client.keys ] && [ ! -L /var/ossec/etc/client.keys ]; then
  cp -n /var/ossec/etc/client.keys "$PERSIST_KEYS" || true
fi

rm -f /var/ossec/etc/client.keys
ln -sf "$PERSIST_KEYS" /var/ossec/etc/client.keys

# -------------------------------------------------
# Enrollment only if no persistent key
# -------------------------------------------------
if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent..."
  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi
else
  echo "[wazuh-agent] client.keys exists; skipping enrollment"
fi

# -------------------------------------------------
# Start agent
# -------------------------------------------------
echo "[wazuh-agent] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
