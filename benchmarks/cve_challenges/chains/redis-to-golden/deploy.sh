#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain 8] Redis to Golden Ticket — 5 steps, DB→Linux→Windows→AD"
echo "  This is the most complete chain: from zero credentials to Enterprise Admin."

# Step 1: Redis (Docker)
echo "=== Step 1: DB-05 Redis Unauthorized ==="
docker compose -f "$ROOT/docker/db/redis-unauth/docker-compose.yml" up -d 2>&1 | tail -2
echo "  [+] Redis at localhost:6379 (no auth)"

# Step 2: Linux PrivEsc (Vagrant)
echo "=== Step 2: LNX-04 vsock UAF kernel exploit ==="
if command -v vagrant &>/dev/null; then
  (cd "$ROOT/docker/linux/kernel-cve-2025-21756" && vagrant up) &
  echo "  [+] LNX-04 VM starting (192.168.57.104)"
else
  echo "  [!] Vagrant not installed"
fi

# Step 3-5: AD scenarios (Docker Samba AD DC for DCSync+Golden Ticket, ESC8 is windows-only)
echo "=== Steps 3-5: AD nodes ==="
AD_COMPOSE="$ROOT/ad/docker-compose.yml"
if ! docker ps --format '{{.Names}}' | grep -q ad-dc01; then
  echo "  [*] Starting Samba AD DC..."
  docker compose -f "$AD_COMPOSE" up -d --build 2>&1 | tail -2
  sleep 15
fi
echo "  [+] AD DC at 192.168.100.10"
echo "  [!] Step 3 (ESC8) requires Windows AD CS — skip for Samba AD"
echo "  [+] Steps 4-5 (DCSync → Golden Ticket) available on Samba AD"
echo ""
echo "[Chain 8] Ready"
echo "  Step 1: redis-cli → write SSH key → flag{chain8-step1-redis}"
echo "  Step 2: CVE-2025-21756 → root → flag{chain8-step2-privesc}"
echo "  Step 3: [windows-only] SMB relay ESC8 → skip or use GOAD"
echo "  Step 4: secretsdump → DCSync → flag{chain8-step4-dcsync}"
echo "  Step 5: ticketer.py → Golden Ticket → flag{chain8-step5-golden-final}"
