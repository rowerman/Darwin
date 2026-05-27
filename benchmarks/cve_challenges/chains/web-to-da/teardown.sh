#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
echo "[Chain 1] Tearing down Web to Domain Admin..."

docker compose -f "$ROOT/docker/web/wordpress-simple-file-list/docker-compose.yml" down -v 2>/dev/null || true
echo "  [+] Docker nodes cleaned"

if command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/nftables-cve-2024-1086" && vagrant halt) 2>/dev/null || true
  echo "  [+] Vagrant nodes halted"
fi

echo "[Chain 1] Teardown complete"
