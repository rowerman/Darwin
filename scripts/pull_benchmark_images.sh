#!/bin/bash
# Pull all Docker base images needed for PACEBench + XBOW benchmarks
# Usage: bash scripts/pull_benchmark_images.sh [--all]

set -uo pipefail

# ── P0: Core images (cover ~80% of all challenges) ──────────────

P0_IMAGES=(
    "php:8.1-apache"
    "python:3.10-slim"
    "node:18-alpine"
    "mysql:8"
)

# ── P1: WAF / reverse-proxy images ──────────────────────────────

P1_IMAGES=(
    "owasp/modsecurity-crs:3.3"
    "nginx:1.24-alpine"
    "ubuntu:22.04"
)

# ── P2: Full coverage ───────────────────────────────────────────

P2_IMAGES=(
    "tomcat:9-jre11"
    "postgres:15-alpine"
    "mongo:6"
    "redis:7-alpine"
)

# ── Pull function ───────────────────────────────────────────────

pull_images() {
    local label="$1"
    shift
    local images=("$@")
    local ok=0 fail=0

    echo "=============================================="
    echo "  $label (${#images[@]} images)"
    echo "=============================================="

    for img in "${images[@]}"; do
        echo -n "  [$img] "
        if docker pull "$img" 2>&1 | tail -1; then
            echo "    -> OK"
            ok=$((ok + 1))
        else
            echo "    -> FAILED"
            fail=$((fail + 1))
        fi
    done

    echo "  Done: $ok pulled, $fail failed"
    echo
}

# ── Main ────────────────────────────────────────────────────────

echo "DARWIN Benchmark Image Puller"
echo "=============================="
echo

pull_images "P0 — Core (PHP/Python/Node/MySQL)" "${P0_IMAGES[@]}"

if [ "${1:-}" = "--all" ]; then
    pull_images "P1 — WAF & Reverse Proxy" "${P1_IMAGES[@]}"
    pull_images "P2 — Full Coverage" "${P2_IMAGES[@]}"
else
    echo "Pulled P0 only. Run with --all to also pull P1/P2 images."
    echo
    echo "  P1: owasp/modsecurity-crs, nginx, ubuntu"
    echo "  P2: tomcat, postgres, mongo, redis"
fi

echo "=============================="
echo "Verify with: docker images | grep -E 'php|python|node|mysql|nginx|tomcat|postgres|mongo|redis|modsecurity'"
