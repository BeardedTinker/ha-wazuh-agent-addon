#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
HA_LOG_FILE="/config/home-assistant.log"

if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key' "$OPTS")"

echo "[wazuh-agent] manager_address=$MANAGER_ADDRESS"
echo "[wazuh-agent] agent_name=$AGENT_NAME"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"

# Required fields
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

##############################################
# Persistent client.keys MUST be prepared first
##############################################
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"
RUNTIME_KEYS="/var/ossec/etc/client.keys"

mkdir -p "$PERSIST_DIR"

# If we already have persisted keys, ensure runtime points to them BEFORE any install/start logic
if [ -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Found persisted client.keys"
else
  echo "[wazuh-agent] No persisted client.keys yet"
fi

# Force runtime keys to be a symlink to persisted keys (idempotent)
rm -f "$RUNTIME_KEYS"
ln -s "$PERSIST_KEYS" "$RUNTIME_KEYS"

##############################################
# Install Wazuh Agent (idempotent)
##############################################
# Install only if binaries are missing, to avoid resetting configs every start
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  echo "[wazuh-agent] Installing Wazuh Agent packages..."
  apt-get update
  apt-get install -y --no-install-recommends wazuh-agent
else
  echo "[wazuh-agent] Wazuh agent already installed; skipping apt install"
fi

# Ensure manager address in config
if [ -f "$CONF" ]; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
fi

##############################################
# Disable container-noisy modules (C-mode)
##############################################
# syscheck/rootcheck are noise in container; we keep them off
for tag in syscheck rootcheck; do
  if grep -q "<${tag}>" "$CONF"; then
    awk -v t="$tag" '
      BEGIN{inblk=0; done=0}
      $0 ~ "<"t">" {inblk=1}
      inblk && !done && $0 ~ "<disabled>no</disabled>" {sub("<disabled>no</disabled>","<disabled>yes</disabled>"); done=1}
      $0 ~ "</"t">" {inblk=0}
      {print}
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
done

##############################################
# HA LOG INGEST (AUTO: file OR journald)
##############################################
add_localfile() {
  local type="$1"
  local value="$2"
  local marker="$3"

  if grep -q "$marker" "$CONF"; then
    echo "[wazuh-agent] HA localfile already configured ($marker)"
    return 0
  fi

  echo "[wazuh-agent] Adding HA localfile ($type)"

  awk -v type="$type" -v val="$value" -v marker="$marker" '
    /<\/ossec_config>/ && !done {
      print "  <!-- " marker " -->"
      print "  <localfile>"
      print "    <log_format>syslog</log_format>"
      if (type == "file") {
        print "    <location>" val "</location>"
      } else {
        print "    <command>" val "</command>"
      }
      print "  </localfile>"
      done=1
    }
    { print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
}

if [ -f "$HA_LOG_FILE" ]; then
  echo "[wazuh-agent] Using HA log file"
  add_localfile "file" "$HA_LOG_FILE" "WAZUH_HA_FILE"
else
  echo "[wazuh-agent] No HA log file found, using journald"
  if command -v journalctl >/dev/null 2>&1; then
    JOURNAL_CMD="journalctl -f -o short-iso CONTAINER_NAME=homeassistant --no-pager"
    add_localfile "command" "$JOURNAL_CMD" "WAZUH_HA_JOURNAL"
  else
    echo "[wazuh-agent] ERROR: journalctl not available"
  fi
fi

##############################################
# Enrollment (ONLY if persisted keys missing/empty)
##############################################
if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent (no persisted client.keys yet)..."

  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -G "$AGENT_GROUP" \
      -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" \
      -p "$ENROLLMENT_PORT" \
      -A "$AGENT_NAME" \
      -P "$ENROLLMENT_KEY"
  fi

  # agent-auth writes to /var/ossec/etc/client.keys (symlink -> persisted file)
  if [ -s "$PERSIST_KEYS" ]; then
    echo "[wazuh-agent] Enrollment succeeded; persisted client.keys created"
  else
    echo "[wazuh-agent] ERROR: Enrollment did not create persisted client.keys"
    exit 1
  fi
else
  echo "[wazuh-agent] Persisted client.keys exists; skipping enrollment"
fi

##############################################
# Start agent
##############################################
echo "[wazuh-agent] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start || true
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing agent log..."
tail -f /var/ossec/logs/ossec.log
