#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

OPTS="/data/options.json"
CONF="/var/ossec/etc/ossec.conf"
KEYS="/var/ossec/etc/client.keys"
PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="$PERSIST_DIR/client.keys"
LOGFILE="/config/home-assistant.log"

# ------------------------------------------------------------
# Validate options.json
# ------------------------------------------------------------

if [ ! -f "$OPTS" ]; then
  echo "[wazuh-agent] ERROR: options.json not found"
  exit 1
fi

MANAGER_ADDRESS="$(jq -r '.manager_address // empty' "$OPTS")"
AGENT_NAME="$(jq -r '.agent_name // empty' "$OPTS")"
AGENT_GROUP="$(jq -r '.agent_group // empty' "$OPTS")"
ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
ENROLLMENT_KEY="$(jq -r '.enrollment_key // empty' "$OPTS")"

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

echo "[wazuh-agent] manager=$MANAGER_ADDRESS agent=$AGENT_NAME"

# ------------------------------------------------------------
# Ensure config exists
# ------------------------------------------------------------

if [ ! -f "$CONF" ]; then
  echo "[wazuh-agent] ERROR: ossec.conf not found"
  exit 1
fi

# ------------------------------------------------------------
# Safely set manager address (only inside <server> block)
# ------------------------------------------------------------

awk -v addr="$MANAGER_ADDRESS" '
BEGIN { in_server=0 }
{
  if ($0 ~ /<server>/) in_server=1
  if ($0 ~ /<\/server>/) in_server=0
  if (in_server && $0 ~ /<address>/) {
    print "    <address>" addr "</address>"
  } else {
    print
  }
}
' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"

# ------------------------------------------------------------
# Disable host-specific modules (container safe)
# ------------------------------------------------------------

for tag in syscheck rootcheck sca syscollector; do
  sed -i "s|<${tag}>|<${tag}><disabled>yes</disabled>|" "$CONF" 2>/dev/null || true
done

# ------------------------------------------------------------
# Configure HA log source (idempotent)
# ------------------------------------------------------------

if grep -q "<log_format>journald</log_format>" "$CONF"; then
  echo "[wazuh-agent] Log source already configured"
else
  if [ -f "$LOGFILE" ]; then
    echo "[wazuh-agent] Using file log source"

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
    echo "[wazuh-agent] Using journald log source"

    awk '
    /<\/ossec_config>/ && !done {
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

# ------------------------------------------------------------
# Persistent client.keys
# ------------------------------------------------------------

mkdir -p "$PERSIST_DIR"

if [ -f "$KEYS" ] && [ ! -L "$KEYS" ]; then
  cp -n "$KEYS" "$PERSIST_KEYS" || true
fi

rm -f "$KEYS"
ln -s "$PERSIST_KEYS" "$KEYS"

# ------------------------------------------------------------
# Enrollment (idempotent)
# ------------------------------------------------------------

if [ ! -s "$PERSIST_KEYS" ]; then
  echo "[wazuh-agent] Performing enrollment"

  set +e
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
  ENROLL_EXIT=$?
  set -e

  if [ $ENROLL_EXIT -ne 0 ]; then
    echo "[wazuh-agent] Enrollment skipped (duplicate or existing agent)"
  fi
else
  echo "[wazuh-agent] Existing client.keys detected — skipping enrollment"
fi

# ------------------------------------------------------------
# Start agent
# ------------------------------------------------------------

echo "[wazuh-agent] Starting agent"
/var/ossec/bin/wazuh-control start

echo "[wazuh-agent] Ready"
tail -f /var/ossec/logs/ossec.log
