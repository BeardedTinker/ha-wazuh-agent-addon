#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
LOGFILE="/config/home-assistant.log"

# --- Preconditions ---
if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found at $OPTS"
  exit 1
fi
if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: ossec.conf not found at $CONF"
  exit 1
fi

# --- Read options ---
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

# --- Required validations ---
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

# --- Persist Wazuh identity across restarts/updates ---
# We keep client.keys under /data (persistent) and symlink it into /var/ossec/etc.
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"
RUNTIME_KEYS="/var/ossec/etc/client.keys"

mkdir -p "$PERSIST_DIR"

# If runtime keys exist (e.g., from package defaults) and persistent does not, seed persistent once.
if [ -s "$RUNTIME_KEYS" ] && [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Seeding persistent client.keys from runtime"
  cp -f "$RUNTIME_KEYS" "$PERSIST_KEYS" || true
fi

# Force runtime path to be a symlink to persistent storage
rm -f "$RUNTIME_KEYS"
ln -sf "$PERSIST_KEYS" "$RUNTIME_KEYS"

# --- Ensure manager address in ossec.conf (best-effort) ---
# Replace <address>...</address> wherever it exists.
sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true

# --- C-mode: disable noisy modules (container != host) ---
# If these blocks exist, flip disabled to yes.
for tag in syscheck rootcheck sca; do
  if grep -q "<${tag}>" "$CONF"; then
    # Flip the first <disabled>no</disabled> inside that block to yes
    awk -v t="$tag" '
      BEGIN{inblk=0; done=0}
      $0 ~ "<"t">" {inblk=1}
      inblk && !done && $0 ~ "<disabled>no</disabled>" {sub("<disabled>no</disabled>","<disabled>yes</disabled>"); done=1}
      $0 ~ "</"t">" {inblk=0}
      {print}
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
done

# --- Add HA log localfile (idempotent) ---
if [ -f "$LOGFILE" ]; then
  if ! grep -q "<location>${LOGFILE}</location>" "$CONF"; then
    echo "[wazuh-agent] Adding localfile for $LOGFILE"
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
    echo "[wazuh-agent] localfile already present for $LOGFILE"
  fi
else
  echo "[wazuh-agent] WARNING: $LOGFILE not found (HA log not present yet)"
fi

# --- Enrollment only if persistent client.keys is empty ---
if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Enrolling agent (no persistent client.keys yet)..."
  if [ -n "$AGENT_GROUP" ]; then
    echo "[wazuh-agent] Enrolling with group: $AGENT_GROUP"
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    echo "[wazuh-agent] Enrolling without group"
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi
else
  echo "[wazuh-agent] persistent client.keys exists; skipping enrollment"
fi

echo "[wazuh-agent] Restarting Wazuh agent..."
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start || true
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing agent log..."
tail -f /var/ossec/logs/ossec.log
