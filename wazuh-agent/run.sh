#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"

PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

LOGFILE="/config/home-assistant.log"

# ----------------------------
# Read options
# ----------------------------
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
DEBUG_DUMP="$(jq -r '.debug_dump_config // true' "$OPTS")"

echo "[wazuh-agent] manager=$MANAGER_ADDRESS agent=$AGENT_NAME"
echo "[wazuh-agent] enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
echo "[wazuh-agent] enrollment_key_set=$([ -n "$ENROLLMENT_KEY" ] && echo yes || echo no)"
echo "[wazuh-agent] agent_group=$AGENT_GROUP"
echo "[wazuh-agent] force_reenroll=$FORCE_REENROLL debug_dump_config=$DEBUG_DUMP"

# ----------------------------
# Required checks
# ----------------------------
if [ -z "$MANAGER_ADDRESS" ]; then
  echo "[wazuh-agent] ERROR: manager_address missing"
  exit 1
fi
if [ -z "$AGENT_NAME" ]; then
  echo "[wazuh-agent] ERROR: agent_name missing"
  exit 1
fi
if [ -z "$ENROLLMENT_KEY" ]; then
  echo "[wazuh-agent] ERROR: enrollment_key missing"
  exit 1
fi

# ----------------------------
# Ensure config exists
# ----------------------------
if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: ossec.conf not found at $CONF"
  exit 1
fi

# ----------------------------
# Persist dir + optional force reenroll
# ----------------------------
mkdir -p "$PERSIST_DIR"

if [ "$FORCE_REENROLL" = "true" ]; then
  echo "[wazuh-agent] Force re-enroll enabled: wiping persisted client.keys"
  rm -f "$PERSIST_KEYS"
fi

# ----------------------------
# Link client.keys -> persisted
# ----------------------------
# If there is a real file already and persisted doesn't exist yet, seed it once.
if [ -f "$KEYS" ] && [ ! -L "$KEYS" ] && [ ! -s "$PERSIST_KEYS" ]; then
  cp -f "$KEYS" "$PERSIST_KEYS" || true
fi

rm -f "$KEYS"
ln -s "$PERSIST_KEYS" "$KEYS"

touch "$PERSIST_KEYS"
chmod 640 "$PERSIST_KEYS" || true
chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true

# ----------------------------
# Set manager address and comm port
# ----------------------------
# Replace the first <address> in the config
sed -i "0,/<address>.*<\/address>/{s|<address>.*<\/address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true
# Replace default 1514 if present
sed -i "s|<port>1514</port>|<port>${COMM_PORT}</port>|" "$CONF" || true

# ----------------------------
# Disable container-noise modules (DO NOT TOUCH SCA)
# ----------------------------
for tag in syscheck rootcheck syscollector; do
  if grep -q "<${tag}>" "$CONF"; then
    # if <disabled> exists inside the block, flip it; else inject it after opening tag
    if awk "/<${tag}>/{f=1} f&&/<disabled>/{print; exit} /<\/${tag}>/{f=0}" "$CONF" | grep -q "<disabled>"; then
      sed -i "0,/<${tag}>/{s/<disabled>no<\/disabled>/<disabled>yes<\/disabled>/}" "$CONF" || true
    else
      awk -v t="$tag" '
        $0 ~ "<"t">" && !done[t] { print; print "    <disabled>yes</disabled>"; done[t]=1; next }
        { print }
      ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
    fi
  fi
done

# ----------------------------
# Add HA log source (file if exists, else journald)
# Journald: include <location>journald</location> to avoid warnings
# ----------------------------
if grep -q "WAZUH-HA" "$CONF"; then
  echo "[wazuh-agent] HA localfile already present"
else
  if [ -f "$LOGFILE" ]; then
    echo "[wazuh-agent] Using file log source: $LOGFILE"
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
    echo "[wazuh-agent] Using journald log source"
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
# Disable auto-enrollment block in ossec.conf (prevents agentd re-enroll w/o password)
# ----------------------------
if grep -q "<enrollment>" "$CONF"; then
  echo "[wazuh-agent] Disabling <enrollment> block in ossec.conf"
  awk '
    BEGIN{skip=0}
    /<enrollment>/{skip=1; next}
    /<\/enrollment>/{skip=0; next}
    { if(!skip) print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# ----------------------------
# Enrollment (ONLY if persisted keys empty)
# ----------------------------
if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] No persisted client.keys; enrolling and capturing keys"
  echo "[wazuh-agent] Performing enrollment"

  if [ -n "$AGENT_GROUP" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  if [ -s "$PERSIST_KEYS" ]; then
    echo "[wazuh-agent] Enrollment complete; client.keys persisted"
  else
    echo "[wazuh-agent] ERROR: Enrollment reported success but persisted client.keys is missing/empty."
    exit 1
  fi
else
  echo "[wazuh-agent] Persisted client.keys exists; skipping enrollment"
fi

# ----------------------------
# Debug: dump config for support (so you can share it without docker attach)
# ----------------------------
if [ "$DEBUG_DUMP" = "true" ]; then
  mkdir -p /share/wazuh-agent || true
  cp -f "$CONF" /share/wazuh-agent/ossec.conf || true
  cp -f "$PERSIST_KEYS" /share/wazuh-agent/client.keys.redacted 2>/dev/null || true
  # Redact keys file if copied (avoid leaking secrets)
  if [ -f /share/wazuh-agent/client.keys.redacted ]; then
    sed -i 's/^\([0-9]\+\) \([^ ]\+\) .*/\1 \2 **REDACTED**/' /share/wazuh-agent/client.keys.redacted || true
  fi
  echo "[wazuh-agent] Debug dump written to /share/wazuh-agent/"
fi

# ----------------------------
# Start agent
# ----------------------------
echo "[wazuh-agent] Starting agent"
if /var/ossec/bin/wazuh-control restart; then
  true
else
  /var/ossec/bin/wazuh-control start || true
fi

echo "[wazuh-agent] Status:"
/var/ossec/bin/wazuh-control status || true

echo "[wazuh-agent] Tailing log..."
tail -f /var/ossec/logs/ossec.log
