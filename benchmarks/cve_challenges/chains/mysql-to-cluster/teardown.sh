#!/bin/bash
ROOT="$(dirname "$(dirname "$(dirname "$0")")")"
docker compose -f "$ROOT/docker/web/mysql-udf/docker-compose.yml" down -v 2>/dev/null || true
kind delete cluster --name cve-chain7-k8s 2>/dev/null || true
echo "[Chain 7] Teardown complete"
