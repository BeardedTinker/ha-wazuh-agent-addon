#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting (placeholder)"
echo "[wazuh-agent] manager_address: ${MANAGER_ADDRESS:-not_set}"

# TODO: install + configure wazuh-agent, enroll to manager, then start service
# For now, keep container alive so HA doesn't instantly mark it as crashed:
tail -f /dev/null
