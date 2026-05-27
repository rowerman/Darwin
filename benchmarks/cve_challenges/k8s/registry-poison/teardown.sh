#!/bin/bash
set -euo pipefail
kind delete cluster --name cve-k8s-09-registry 2>/dev/null || true
docker rm -f k8s-registry 2>/dev/null || true
