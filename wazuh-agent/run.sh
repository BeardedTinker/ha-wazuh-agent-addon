#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log() { echo "[wazuh-agent] $*"; }

OPTS="/data/options.json"

CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"

# Persist inside add-on data (maps to host add-on data)
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

LOGFILE="/config/home-assistant.log"

# ----------------------------
# Read options
# ----------------------------
if [[ ! -f "$OPTS" ]]; then
  log "ERROR: options.json not found at $OPTS"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address // empty' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name // empty' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // ""' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port // 1514' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key // empty' "$OPTS")"
FORCE_REENROLL="$(jq -r '.force_reenroll // false' "$OPTS")"
DEBUG_DUMP="$(jq -r '.debug_dump_config // false' "$OPTS")"

log "Starting"
log "manager=$MANAGER_ADDRESS agent=$AGENT_NAME"
log "enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
log "enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"
log "agent_group=$AGENT_GROUP"
log "force_reenroll=$FORCE_REENROLL debug_dump_config=$DEBUG_DUMP"

# Required checks
if [[ -z "$MANAGER_ADDRESS" ]]; then log "ERROR: manager_address missing"; exit 1; fi
if [[ -z "$AGENT_NAME" ]]; then log "ERROR: agent_name missing"; exit 1; fi
if [[ -z "$ENROLLMENT_KEY" ]]; then log "ERROR: enrollment_key missing"; exit 1; fi

# Ensure config exists
if [[ ! -f "$CONF" ]]; then
  log "ERROR: ossec.conf not found at $CONF"
  exit 1
fi

# ----------------------------
# Persist dir + optional force reenroll
# ----------------------------
mkdir -p "$PERSIST_DIR"

if [[ "$FORCE_REENROLL" == "true" ]]; then
  log "Force re-enroll enabled: wiping persisted client.keys"
  rm -f "$PERSIST_KEYS"
fi

# Ensure persisted file exists (may be empty)
touch "$PERSIST_KEYS"
chmod 640 "$PERSIST_KEYS" || true
chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true

# ----------------------------
# Apply manager address + comm port
# ----------------------------
sed -i "0,/<address>.*<\/address>/{s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true
sed -i "s|<port>1514</port>|<port>${COMM_PORT}</port>|" "$CONF" || true

# ----------------------------
# Remove <enrollment> block (avoid agentd auto-enrolling without password)
# ----------------------------
if grep -q "<enrollment>" "$CONF"; then
  log "Removing <enrollment> block from ossec.conf (avoid auto-enroll)"
  awk '
    BEGIN{skip=0}
    /<enrollment>/{skip=1; next}
    /<\/enrollment>/{skip=0; next}
    { if(!skip) print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# ----------------------------
# Add HA log source (file if exists, otherwise journald)
# ----------------------------
if grep -q "WAZUH-HA" "$CONF"; then
  log "HA localfile already present"
else
  if [[ -f "$LOGFILE" ]]; then
    log "Using file log source: $LOGFILE"
    awk -v lf="$LOGFILE" '
      /<\/ossec_config>/ && !done {
        print "  <!-- WAZUH-HA: Home Assistant log file -->"
        print "  <localfile>"
        print "    <log_format>syslog</log_format>"
        print "    <location>" lf "</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  else
    log "Using journald log source"
    awk '
      /<\/ossec_config>/ && !done {
        print "  <!-- WAZUH-HA: Home Assistant journald -->"
        print "  <localfile>"
        print "    <log_format>journald</log_format>"
        print "    <location>journald</location>"
        print "  </localfile>"
        done=1
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
fi

# ----------------------------
# KEY HANDLING (NO SYMLINK!)
# 1) If persisted keys exist -> copy into /var/ossec/etc/client.keys
# 2) Else enroll -> client.keys will be created in /var/ossec/etc -> copy to persisted
# ----------------------------

if [[ -s "$PERSIST_KEYS" ]]; then
  log "Persisted client.keys exists; restoring into /var/ossec/etc/client.keys"
  cp -f "$PERSIST_KEYS" "$KEYS"
  chmod 640 "$KEYS" || true
  chown root:wazuh "$KEYS" 2>/dev/null || true
else
  log "No persisted client.keys; enrolling now"

  if [[ -n "$AGENT_GROUP" ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  if [[ -s "$KEYS" ]]; then
    log "Enrollment complete; persisting client.keys"
    cp -f "$KEYS" "$PERSIST_KEYS"
    chmod 640 "$PERSIST_KEYS" || true
    chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true
  else
    log "ERROR: Enrollment reported success but /var/ossec/etc/client.keys is missing/empty."
    exit 1
  fi
fi

# ----------------------------
# Debug dump (prints to add-on logs)
# ----------------------------
if [[ "$DEBUG_DUMP" == "true" ]]; then
  log "DEBUG: options.json:"
  cat "$OPTS" || true

  log "DEBUG: persisted keys:"
  ls -la "$PERSIST_DIR" || true
  wc -c "$PERSIST_KEYS" 2>/dev/null || true

  log "DEBUG: live keys:"
  ls -la /var/ossec/etc || true
  wc -c "$KEYS" 2>/dev/null || true

  log "DEBUG: journald mounts:"
  ls -la /run/log/journal 2>/dev/null || true
  ls -la /var/log/journal 2>/dev/null || true

  log "DEBUG: ossec.conf grep enrollment/localfile:"
  grep -nE "<enrollment>|</enrollment>|WAZUH-HA|<localfile>|journald" "$CONF" || true
fi

# ----------------------------
# Start agent
# ----------------------------
log "Starting agent"
/var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start

log "Status:"
/var/ossec/bin/wazuh-control status || true

log "Tailing log..."
tail -f /var/ossec/logs/ossec.log
