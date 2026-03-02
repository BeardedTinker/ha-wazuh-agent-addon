#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="$PERSIST_DIR/client.keys"
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

# ------------------------------------------------------------
# REQUIRED CHECKS
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# INSTALL WAZUH AGENT (NON-INTERACTIVE SAFE)
# ------------------------------------------------------------

if [ ! -d /var/ossec ]; then
  echo "[wazuh-agent] Installing Wazuh agent..."

  apt-get update
  apt-get install -y curl ca-certificates gnupg jq

  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.key
  gpg --batch --yes --dearmor /tmp/wazuh.key
  mv /tmp/wazuh.key.gpg /usr/share/keyrings/wazuh.gpg
  rm /tmp/wazuh.key

  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
    > /etc/apt/sources.list.d/wazuh.list

  apt-get update
  apt-get install -y wazuh-agent
fi

# ------------------------------------------------------------
# ENSURE CONFIG EXISTS
# ------------------------------------------------------------

if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: ossec.conf not found after install"
  exit 1
fi

# ------------------------------------------------------------
# SET MANAGER ADDRESS
# ------------------------------------------------------------

sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF"

# ------------------------------------------------------------
# DISABLE HOST-SPECIFIC MODULES (CONTAINER SAFE MODE)
# ------------------------------------------------------------

for tag in syscheck rootcheck sca syscollector; do
  if grep -q "<${tag}>" "$CONF"; then
    sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF"
  fi
done

# ------------------------------------------------------------
# ADD HOME ASSISTANT LOG SOURCE
# ------------------------------------------------------------

if grep -q "$LOGFILE" "$CONF"; then
  echo "[wazuh-agent] HA localfile already configured"
else
  if [ -f "$LOGFILE" ]; then
    echo "[wazuh-agent] Adding HA log file source"

    awk -v lf="$LOGFILE" '
      /<\/ossec_config>/ && !done {
        print "  <localfile>"
        print "    <log_format>syslog</log_format>"
        print "    <location>" lf "</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"

  else
    echo "[wazuh-agent] No HA log file found, using journald"

    awk '
      /<\/ossec_config>/ && !done {
        print "  <localfile>"
        print "    <log_format>journald</log_format>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
fi

# ------------------------------------------------------------
# PERSISTENT client.keys
# ------------------------------------------------------------

mkdir -p "$PERSIST_DIR"

if [ -f "$KEYS" ] && [ ! -L "$KEYS" ]; then
  cp -n "$KEYS" "$PERSIST_KEYS" || true
fi

rm -f "$KEYS"
ln -s "$PERSIST_KEYS" "$KEYS"

# ------------------------------------------------------------
# ENROLL ONLY IF NO VALID KEYS
# ------------------------------------------------------------

if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent..."

  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth \
      -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -G "$AGENT_GROUP" \
      -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth \
      -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -P "$ENROLLMENT_KEY"
  fi
else
  echo "[wazuh-agent] client.keys exists, skipping enrollment"
fi

# ------------------------------------------------------------
# START AGENT
# ------------------------------------------------------------

echo "[wazuh-agent] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
