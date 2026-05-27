#!/bin/bash
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
docker compose -f "$ROOT/docker/db/redis-unauth/docker-compose.yml" down -v 2>/dev/null || true
echo "[Chain 8] Docker nodes cleaned. Halt GOAD VMs manually."
