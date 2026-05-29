#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-15-image-tag
docker compose -f /home/kianabin/Darwin/benchmarks/cve_challenges/k8s/mutable-image-tag/registry-compose.yml down -v 2>/dev/null || true
