#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
LOGFILE="/config/home-assistant.log"

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

# Required
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

# Ensure manager address in config (best-effort)
if [ -f "$CONF" ]; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
fi

# --- C-mode: disable noisy modules (container != host) ---
# Disable syscheck/rootcheck/sca (idempotent edits)
# If blocks exist, flip to no; if not, we don't force-add them here (keeps minimal edits).
for tag in syscheck rootcheck sca; do
  if grep -q "<${tag}>" "$CONF"; then
    sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF" || true
  fi
done

# --- Add HA log localfile (idempotent) ---
if [ -f "$LOGFILE" ]; then
  if ! grep -q "$LOGFILE" "$CONF"; then
    echo "[wazuh-agent] Adding localfile for $LOGFILE"
    # Insert before closing tag
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
  else
    echo "[wazuh-agent] localfile already present"
  fi
else
  echo "[wazuh-agent] WARNING: $LOGFILE not found (HA log not present yet)"
fi

mkdir -p /data/ossec/etc

# Persist client.keys across restarts/updates
if [ -f /var/ossec/etc/client.keys ] && [ ! -L /var/ossec/etc/client.keys ]; then
  cp -n /var/ossec/etc/client.keys /data/ossec/etc/client.keys || true
fi

rm -f /var/ossec/etc/client.keys
ln -s /data/ossec/etc/client.keys /var/ossec/etc/client.keys

# --- Enrollment only if client.keys is missing/empty ---
KEYS="/var/ossec/etc/client.keys"
if [ ! -s "$KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent (no client.keys yet)..."
  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi
else
  echo "[wazuh-agent] client.keys exists; skipping enrollment"
fi

echo "[wazuh-agent] Restarting Wazuh agent..."
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start || true
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing agent log..."
tail -f /var/ossec/logs/ossec.log
