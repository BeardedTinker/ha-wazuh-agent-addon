#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"

PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

KEYS="/var/ossec/etc/client.keys"

# -----------------------------
# Read options
# -----------------------------
if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found at $OPTS"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address // empty' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name // empty' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port // 1514' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key // empty' "$OPTS")"
FORCE_REENROLL="$(jq -r '.force_reenroll // false' "$OPTS")"

echo "[wazuh-agent] manager=${MANAGER_ADDRESS} agent=${AGENT_NAME}"
echo "[wazuh-agent] enrollment_port=${ENROLLMENT_PORT} comm_port=${COMM_PORT}"
echo "[wazuh-agent] enrollment_key_set=$([ -n "${ENROLLMENT_KEY}" ] && echo yes || echo no)"
echo "[wazuh-agent] agent_group=${AGENT_GROUP:-}"
echo "[wazuh-agent] force_reenroll=${FORCE_REENROLL}"

# -----------------------------
# Required checks
# -----------------------------
if [ -z "$MANAGER_ADDRESS" ]; then
  echo "[wazuh-agent] ERROR: manager_address is required"
  exit 1
fi
if [ -z "$AGENT_NAME" ]; then
  echo "[wazuh-agent] ERROR: agent_name is required"
  exit 1
fi
if [ -z "$ENROLLMENT_KEY" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key is required"
  exit 1
fi

# -----------------------------
# Validate Wazuh install
# -----------------------------
if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: $CONF not found. wazuh-agent install looks broken."
  exit 1
fi

# -----------------------------
# Ensure persistence dir exists
# -----------------------------
mkdir -p "$PERSIST_DIR"

# Optional: force re-enrollment (wipe persisted keys)
if [ "$FORCE_REENROLL" = "true" ]; then
  echo "[wazuh-agent] Force re-enroll enabled: wiping persisted client.keys"
  rm -f "$PERSIST_KEYS"
fi

# -----------------------------
# Ensure manager address/ports
# -----------------------------
sed -i "s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|" "$CONF" || true
sed -i "s|<port>.*</port>|<port>${COMM_PORT}</port>|" "$CONF" || true

# -----------------------------
# SELF-HEAL: remove invalid <disabled> inside <sca>...</sca>
# -----------------------------
if awk 'BEGIN{sca=0;bad=0}
  /<sca>/{sca=1}
  sca && /<disabled>/{bad=1}
  /<\/sca>/{sca=0}
  END{exit(bad?0:1)}' "$CONF"; then
  echo "[wazuh-agent] Detected invalid <disabled> inside <sca>. Removing it (self-heal)."
  awk '
    BEGIN{sca=0}
    /<sca>/{sca=1}
    sca && /<disabled>/{next}
    /<\/sca>/{sca=0}
    {print}
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# -----------------------------
# Ensure journald localfile source (idempotent)
# -----------------------------
if grep -q "<log_format>journald</log_format>" "$CONF"; then
  echo "[wazuh-agent] Journald localfile already present"
else
  echo "[wazuh-agent] Adding journald localfile source"
  awk '
    /<\/ossec_config>/ && !done {
      print "  <localfile>";
      print "    <log_format>journald</log_format>";
      print "    <location>journald</location>";
      print "  </localfile>";
      done=1
    }
    { print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# -----------------------------
# Key handling (PRODUCTION FIX):
# - If persisted keys exist: ensure symlink and skip enrollment
# - Else: enrollment writes to a REAL file at /var/ossec/etc/client.keys
#   then we copy to persisted location, then create symlink
# -----------------------------

if [ -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Persisted client.keys found; using it and skipping enrollment"
  rm -f "$KEYS"
  ln -s "$PERSIST_KEYS" "$KEYS"
else
  echo "[wazuh-agent] No persisted client.keys; enrolling and capturing keys"

  # IMPORTANT: do NOT symlink before enrollment
  rm -f "$KEYS"
  : > "$KEYS"
  chmod 600 "$KEYS" || true

  echo "[wazuh-agent] Performing enrollment"
  set +e
  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi
  ENROLL_RC=$?
  set -e

  if [ $ENROLL_RC -ne 0 ]; then
    echo "[wazuh-agent] ERROR: Enrollment failed."
    echo "[wazuh-agent] Most common cause: agent with the same name already exists on the manager."
    echo "[wazuh-agent] Fix options:"
    echo "[wazuh-agent]  1) Delete existing agent on manager (same name) and restart add-on"
    echo "[wazuh-agent]  2) Change agent_name in add-on config"
    exit 1
  fi

  if [ ! -s "$KEYS" ]; then
    echo "[wazuh-agent] ERROR: Enrollment succeeded but $KEYS is empty/missing (unexpected)."
    exit 1
  fi

  # Copy keys to persistent storage
  cp -f "$KEYS" "$PERSIST_KEYS"
  chmod 600 "$PERSIST_KEYS" || true

  # Replace with symlink for future runs
  rm -f "$KEYS"
  ln -s "$PERSIST_KEYS" "$KEYS"

  echo "[wazuh-agent] Enrollment complete; client.keys persisted"
fi

# -----------------------------
# Start agent
# -----------------------------
echo "[wazuh-agent] Starting agent"
 /var/ossec/bin/wazuh-control start || true

echo "[wazuh-agent] Status:"
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
