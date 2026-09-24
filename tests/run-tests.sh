#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/wazuh-agent/run.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if ! is_port 1514 || ! is_port 65535; then
  fail "valid ports were rejected"
fi
if is_port 0 || is_port 65536 || is_port invalid; then
  fail "invalid ports were accepted"
fi

for address in \
  192.168.1.10 \
  wazuh-manager.local \
  2001:db8::1 \
  fe80::1%eth0; do
  if ! is_manager_address "$address"; then
    fail "valid manager address was rejected: $address"
  fi
done

for address in \
  "" \
  "manager address" \
  'manager&other' \
  'manager|other' \
  '<manager>' \
  '$(id)'; do
  if is_manager_address "$address"; then
    fail "unsafe manager address was accepted: $address"
  fi
done

if is_manager_address "$(printf 'a%.0s' {1..256})"; then
  fail "overlong manager address was accepted"
fi

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
export MOCK_STATE="$TEST_DIR/state"
export MOCK_ACTIONS="$TEST_DIR/actions"
WAZUH_CONTROL="$TEST_DIR/wazuh-control"
export WAZUH_CONTROL

cat > "$WAZUH_CONTROL" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "$1" >> "$MOCK_ACTIONS"
case "$1" in
  status)
    if [[ "$(< "$MOCK_STATE")" == "running" ]]; then
      echo "wazuh-agentd is running..."
      echo "wazuh-logcollector is running..."
    else
      echo "wazuh-agentd is not running..."
      echo "wazuh-logcollector is not running..."
    fi
    ;;
  start|restart)
    [[ "${MOCK_START_FAIL:-false}" != "true" ]] || exit 1
    [[ "${MOCK_START_NOOP:-false}" == "true" ]] || echo "running" > "$MOCK_STATE"
    ;;
  stop)
    echo "stopped" > "$MOCK_STATE"
    ;;
esac
EOF
chmod +x "$WAZUH_CONTROL"

echo "running" > "$MOCK_STATE"
if ! agent_is_running; then
  fail "running agent was not detected"
fi

echo "stopped" > "$MOCK_STATE"
if agent_is_running; then
  fail "stopped agent was reported as running"
fi

start_agent >/dev/null
if [[ "$(< "$MOCK_STATE")" != "running" ]] || ! grep -q '^start$' "$MOCK_ACTIONS"; then
  fail "stopped agent was not started"
fi

start_agent >/dev/null
if ! grep -q '^restart$' "$MOCK_ACTIONS"; then
  fail "running agent was not restarted"
fi

echo "stopped" > "$MOCK_STATE"
export MOCK_START_FAIL=true
if start_agent >/dev/null; then
  fail "start command failure was ignored"
fi
unset MOCK_START_FAIL

export MOCK_START_NOOP=true
if start_agent >/dev/null; then
  fail "failed post-start status check was ignored"
fi
unset MOCK_START_NOOP

echo "agent-key" > "$TEST_DIR/source.keys"
copy_client_keys "$TEST_DIR/source.keys" "$TEST_DIR/destination.keys" "persist"
if ! cmp -s "$TEST_DIR/source.keys" "$TEST_DIR/destination.keys"; then
  fail "client.keys content was not copied"
fi
if copy_client_keys "$TEST_DIR/source.keys" "$TEST_DIR/missing/destination.keys" "persist" >/dev/null 2>&1; then
  fail "client.keys copy failure was ignored"
fi

echo "All Wazuh Agent shell tests passed"
