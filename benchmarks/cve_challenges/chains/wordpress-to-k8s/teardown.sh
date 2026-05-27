#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

docker compose -f "$ROOT/docker/web/wordpress-simple-file-list/docker-compose.yml" down -v 2>/dev/null || true
docker compose -f "$ROOT/docker/db/mysql-udf-direct/docker-compose.yml" down -v 2>/dev/null || true
kind delete cluster --name cve-chain3-k8s 2>/dev/null || true
rm -rf $HOME/.cache/cve-challenges/chain3-flags

if command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/nftables-cve-2024-26809" && vagrant halt) 2>/dev/null || true
fi
echo "[Chain 3] Teardown complete"
