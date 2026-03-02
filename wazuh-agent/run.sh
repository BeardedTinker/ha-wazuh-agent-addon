#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log() { echo "[wazuh-agent] $*"; }

OPTS="/data/options.json"

CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"

# Persist inside addon data (maps to /addon_configs/<slug>/ on host)
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

# Optional HA file log (usually not present)
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

# Ensure base config exists
if [[ ! -f "$CONF" ]]; then
  log "ERROR: ossec.conf not found at $CONF (wazuh-agent package broken?)"
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

# ----------------------------
# Link client.keys -> persisted
# ----------------------------
# If a real keys file exists and persisted is empty, seed it once.
if [[ -f "$KEYS" && ! -L "$KEYS" && ! -s "$PERSIST_KEYS" ]]; then
  cp -f "$KEYS" "$PERSIST_KEYS" || true
fi

rm -f "$KEYS"
ln -s "$PERSIST_KEYS" "$KEYS"

touch "$PERSIST_KEYS"
chmod 640 "$PERSIST_KEYS" || true
# group 'wazuh' exists after package install; ignore if not
chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true

# ----------------------------
# Set manager address + comm port
# ----------------------------
# Replace first <address>...</address>
sed -i "0,/<address>.*<\/address>/{s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true
# Replace common default 1514 port line if present
sed -i "s|<port>1514</port>|<port>${COMM_PORT}</port>|" "$CONF" || true

# ----------------------------
# Ensure NO auto-enrollment block
# (prevents wazuh-agentd from enrolling again without password)
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
# Add HA log source
# Prefer file if exists, else journald
# Journald should include <location>journald</location> to avoid warnings
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
# Enrollment (ONLY if persisted keys empty)
# ----------------------------
if [[ ! -s "$PERSIST_KEYS" ]]; then
  log "No persisted client.keys; enrolling now"
  if [[ -n "$AGENT_GROUP" ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  # Verify keys actually exist (symlink target)
  if [[ -s "$PERSIST_KEYS" ]]; then
    log "Enrollment complete; client.keys persisted"
  else
    log "ERROR: Enrollment reported success but persisted client.keys is missing/empty."
    log "DEBUG: KEYS points to: $(readlink -f "$KEYS" || true)"
    log "DEBUG: listing /var/ossec/etc:"
    ls -la /var/ossec/etc || true
    log "DEBUG: listing $PERSIST_DIR:"
    ls -la "$PERSIST_DIR" || true
    exit 1
  fi
else
  log "Persisted client.keys exists; skipping enrollment"
fi

# ----------------------------
# Debug dump (so you can get ossec.conf without container access)
# ----------------------------
if [[ "$DEBUG_DUMP" == "true" ]]; then
  log "DEBUG DUMP: ossec.conf (first 220 lines)"
  sed -n '1,220p' "$CONF" || true
  log "DEBUG DUMP: ossec.conf (last 120 lines)"
  tail -n 120 "$CONF" || true

  log "DEBUG DUMP: keys + storage"
  log "KEYS symlink: $(ls -la "$KEYS" 2>/dev/null || true)"
  log "PERSIST_KEYS: $(ls -la "$PERSIST_KEYS" 2>/dev/null || true)"
  log "PERSIST_DIR:"
  ls -la "$PERSIST_DIR" || true
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
