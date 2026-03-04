#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log() { echo "[wazuh-agent] $*"; }

OPTS="/data/options.json"

CONF="/var/ossec/etc/ossec.conf"
LIVE_KEYS="/var/ossec/etc/client.keys"

PERSIST_DIR="/data/ossec/etc"
PERSIST_KEYS="${PERSIST_DIR}/client.keys"

LOGFILE="/config/home-assistant.log"

MACHINE_ID_FILE="/data/machine-id"
JOURNAL_ROOT="/var/log/journal"

# ----------------------------
# Ensure /etc/machine-id exists (needed for journald in containers)
# Persist it in /data/machine-id so it survives addon restart/reinstall.
# ----------------------------
ensure_machine_id() {
  mkdir -p /data

  # If /etc/machine-id already exists, make sure we also persist it (if missing)
  if [[ -s /etc/machine-id ]]; then
    if [[ ! -s "$MACHINE_ID_FILE" ]]; then
      log "Persisting existing /etc/machine-id into $MACHINE_ID_FILE"
      head -c 32 /etc/machine-id > "$MACHINE_ID_FILE" || true
      chmod 0444 "$MACHINE_ID_FILE" || true
    fi
    log "/etc/machine-id exists"
    return 0
  fi

  # 1) If we already have persisted machine-id, use it
  if [[ -s "$MACHINE_ID_FILE" ]]; then
    log "Restoring /etc/machine-id from $MACHINE_ID_FILE"
    install -m 0444 -o root -g root "$MACHINE_ID_FILE" /etc/machine-id
    return 0
  fi

  # 2) Try infer from journald directory name: /var/log/journal/<machineid>
  local inferred=""
  if [[ -d "$JOURNAL_ROOT" ]]; then
    inferred="$(find "$JOURNAL_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
      | grep -E '^[0-9a-f]{32}$' | head -n 1 || true)"
  fi

  if [[ -n "$inferred" ]]; then
    log "Inferred machine-id from journald dir: $inferred"
    echo "$inferred" > "$MACHINE_ID_FILE"
    chmod 0444 "$MACHINE_ID_FILE" || true
    install -m 0444 -o root -g root "$MACHINE_ID_FILE" /etc/machine-id
    return 0
  fi

  # 3) Fallback: generate new 32-hex id (persisted to /data)
  local gen=""
  if command -v openssl >/dev/null 2>&1; then
    gen="$(openssl rand -hex 16)"
  else
    gen="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi

  log "Generated new machine-id: $gen"
  echo "$gen" > "$MACHINE_ID_FILE"
  chmod 0444 "$MACHINE_ID_FILE" || true
  install -m 0444 -o root -g root "$MACHINE_ID_FILE" /etc/machine-id
}

ensure_machine_id
log "machine-id: $(head -c 32 /etc/machine-id 2>/dev/null || echo missing)"

# ----------------------------
# Helpers
# ----------------------------
jq_str() {
  local key="$1"
  local val
  val="$(jq -r "$key" "$OPTS" 2>/dev/null || true)"
  [[ "$val" == "null" ]] && echo "" || echo "$val"
}

is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

# Disable/enable <syscheck> / <rootcheck> blocks safely
set_disabled_simple_block() {
  local tag="$1"
  local want_disabled="$2" # "yes" or "no"

  if ! grep -q "<${tag}>" "$CONF"; then
    return 0
  fi

  # If <disabled> exists in the block, replace first occurrence
  if awk "/<${tag}>/{f=1} f&&/<disabled>/{print; exit} /<\/${tag}>/{f=0}" "$CONF" | grep -q "<disabled>"; then
    awk -v t="$tag" -v v="$want_disabled" '
      BEGIN{f=0;done=0}
      $0 ~ "<"t">" {f=1}
      f && !done && $0 ~ /<disabled>/ {
        gsub(/<disabled>[^<]*<\/disabled>/, "<disabled>"v"</disabled>")
        done=1
      }
      $0 ~ "</"t">" {f=0}
      {print}
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  else
    awk -v t="$tag" -v v="$want_disabled" '
      $0 ~ "<"t">" && !done {
        print
        print "    <disabled>"v"</disabled>"
        done=1
        next
      }
      { print }
    ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
  fi
}

# Disable syscollector whether it appears as <syscollector> or <wodle name="syscollector">
disable_syscollector_any_shape() {
  if grep -q "<syscollector>" "$CONF"; then
    set_disabled_simple_block "syscollector" "yes"
  fi

  if grep -q '<wodle name="syscollector">' "$CONF"; then
    if awk '/<wodle name="syscollector">/{f=1} f&&/<disabled>/{print; exit} /<\/wodle>/{f=0}' "$CONF" | grep -q "<disabled>"; then
      awk '
        BEGIN{f=0;done=0}
        /<wodle name="syscollector">/{f=1}
        f && !done && /<disabled>/{
          gsub(/<disabled>[^<]*<\/disabled>/, "<disabled>yes</disabled>")
          done=1
        }
        /<\/wodle>/{f=0}
        {print}
      ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
    else
      awk '
        /<wodle name="syscollector">/ && !done {
          print
          print "    <disabled>yes</disabled>"
          done=1
          next
        }
        {print}
      ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
    fi
  fi
}

# Remove default "command" localfile collectors (df/netstat/last) — they are noisy in containers
remove_command_collectors() {
  awk '
    BEGIN{inlf=0;buf="";hascmd=0}
    /<localfile>/{inlf=1;buf=$0"\n";hascmd=0;next}
    inlf{
      buf=buf $0"\n"
      if ($0 ~ /<command>/) hascmd=1
      if ($0 ~ /<\/localfile>/){
        if (!hascmd) printf "%s", buf
        inlf=0;buf="";hascmd=0
      }
      next
    }
    {print}
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
}

# ----------------------------
# Read options
# ----------------------------
if [[ ! -f "$OPTS" ]]; then
  log "ERROR: options.json not found"
  exit 1
fi

MANAGER_ADDRESS="$(jq_str '.manager_address')"
AGENT_NAME="$(jq_str '.agent_name')"
AGENT_GROUP="$(jq_str '.agent_group // ""')"

ENROLLMENT_PORT="$(jq -r '.enrollment_port // 1515' "$OPTS")"
COMM_PORT="$(jq -r '.communication_port // 1514' "$OPTS")"

ENROLLMENT_KEY="$(jq_str '.enrollment_key')"
FORCE_REENROLL="$(jq -r '.force_reenroll // false' "$OPTS")"
DEBUG_DUMP="$(jq -r '.debug_dump_config // false' "$OPTS")"
SECURITY_PROFILE="$(jq -r '.security_profile // "minimal"' "$OPTS")"

log "Starting"
log "manager=$MANAGER_ADDRESS agent=$AGENT_NAME"
log "enrollment_port=$ENROLLMENT_PORT comm_port=$COMM_PORT"
log "enrollment_key_set=$([[ -n "$ENROLLMENT_KEY" ]] && echo yes || echo no)"
log "agent_group=$AGENT_GROUP"
log "force_reenroll=$FORCE_REENROLL debug_dump_config=$DEBUG_DUMP"
log "security_profile=$SECURITY_PROFILE"

# ----------------------------
# Validation
# ----------------------------
[[ -n "$MANAGER_ADDRESS" ]] || { log "ERROR: manager_address missing"; exit 1; }
[[ -n "$AGENT_NAME" ]] || { log "ERROR: agent_name missing"; exit 1; }
[[ -n "$ENROLLMENT_KEY" ]] || { log "ERROR: enrollment_key missing"; exit 1; }

is_port "$ENROLLMENT_PORT" || { log "ERROR: enrollment_port must be 1..65535 (got: $ENROLLMENT_PORT)"; exit 1; }
is_port "$COMM_PORT" || { log "ERROR: communication_port must be 1..65535 (got: $COMM_PORT)"; exit 1; }

# ----------------------------
# Sanity: wazuh installed
# ----------------------------
if [[ ! -x /var/ossec/bin/wazuh-control ]] || [[ ! -f "$CONF" ]]; then
  log "ERROR: Wazuh agent not present. Rebuild image (Dockerfile installs wazuh-agent)."
  exit 1
fi

# ----------------------------
# Persisted keys handling (copy, not symlink)
# ----------------------------
mkdir -p "$PERSIST_DIR"

if [[ "$FORCE_REENROLL" == "true" ]]; then
  log "Force re-enroll enabled: wiping persisted client.keys"
  rm -f "$PERSIST_KEYS"
fi

touch "$PERSIST_KEYS"
chmod 640 "$PERSIST_KEYS" || true
chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true

if [[ -s "$PERSIST_KEYS" ]]; then
  log "Persisted client.keys exists; restoring into $LIVE_KEYS"
  cp -f "$PERSIST_KEYS" "$LIVE_KEYS" || true
  chmod 640 "$LIVE_KEYS" || true
  chown root:wazuh "$LIVE_KEYS" 2>/dev/null || true
fi

# ----------------------------
# Manager address/port
# ----------------------------
sed -i "0,/<address>.*<\/address>/{s|<address>.*</address>|<address>${MANAGER_ADDRESS}</address>|}" "$CONF" || true
sed -i "0,/<port>[0-9]\+<\/port>/{s|<port>[0-9]\+</port>|<port>${COMM_PORT}</port>|}" "$CONF" || true

# ----------------------------
# Add HA log source (file or journald)
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
# Disable auto-enrollment block (critical)
# ----------------------------
if grep -q "<enrollment>" "$CONF"; then
  log "Disabling <enrollment> block in ossec.conf"
  awk '
    BEGIN{skip=0}
    /<enrollment>/{skip=1; next}
    /<\/enrollment>/{skip=0; next}
    { if(!skip) print }
  ' "$CONF" > /tmp/ossec.conf && mv /tmp/ossec.conf "$CONF"
fi

# ----------------------------
# Apply security profile
# minimal: keep SCA (don’t touch), disable noisy host modules + command collectors
# ----------------------------
if [[ "$SECURITY_PROFILE" == "minimal" ]]; then
  log "Applying minimal security profile: disable syscheck/rootcheck/syscollector + command collectors"
  set_disabled_simple_block "syscheck" "yes"
  set_disabled_simple_block "rootcheck" "yes"
  disable_syscollector_any_shape
  remove_command_collectors
fi

# ----------------------------
# Enrollment if no persisted keys
# ----------------------------
if [[ ! -s "$PERSIST_KEYS" ]]; then
  log "No persisted client.keys; enrolling now"

  if [[ -n "$AGENT_GROUP" ]]; then
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP" -P "$ENROLLMENT_KEY"
  else
    /var/ossec/bin/agent-auth -m "$MANAGER_ADDRESS" -p "$ENROLLMENT_PORT" -A "$AGENT_NAME" -P "$ENROLLMENT_KEY"
  fi

  if [[ -s "$LIVE_KEYS" ]]; then
    log "Enrollment complete; persisting client.keys"
    cp -f "$LIVE_KEYS" "$PERSIST_KEYS" || true
    chmod 640 "$PERSIST_KEYS" || true
    chown root:wazuh "$PERSIST_KEYS" 2>/dev/null || true
  else
    log "ERROR: Enrollment reported success but live client.keys is missing/empty."
    exit 1
  fi
fi

# ----------------------------
# Debug dump
# ----------------------------
if [[ "$DEBUG_DUMP" == "true" ]]; then
  log "DEBUG: persisted keys size:"
  wc -c "$PERSIST_KEYS" 2>/dev/null || true
  log "DEBUG: live keys size:"
  wc -c "$LIVE_KEYS" 2>/dev/null || true
  log "DEBUG: ossec.conf key lines:"
  grep -nE "WAZUH-HA|<localfile>|journald|<address>|<port>|<enrollment>|<syscheck>|<rootcheck>|syscollector|<command>" "$CONF" || true
fi

# ----------------------------
# Start agent
# ----------------------------
log "Starting agent"
if /var/ossec/bin/wazuh-control status >/dev/null 2>&1; then
  /var/ossec/bin/wazuh-control restart || true
else
  /var/ossec/bin/wazuh-control start || true
fi

log "Status:"
/var/ossec/bin/wazuh-control status || true

log "Tailing log..."
tail -f /var/ossec/logs/ossec.log
