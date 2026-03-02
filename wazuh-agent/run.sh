#!/usr/bin/env bash
set -euo pipefail

echo "[wazuh-agent] Starting"

if [ -f /data/options.json ]; then
  echo "[wazuh-agent] options.json found"
  echo "[wazuh-agent] Raw options:"
  cat /data/options.json
else
  echo "[wazuh-agent] options.json NOT found"
fi

# keep container alive for now
tail -f /dev/null
